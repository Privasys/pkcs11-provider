package main

/*
#include "cryptoki.h"
*/
import "C"

import (
	"sync"
	"unsafe"
)

// An object is one vault key. An EC signing key surfaces as a CKO_PRIVATE_KEY
// (CKK_EC) — the consumption surface (C_Sign) the vault backs in-enclave — plus
// a CKO_PUBLIC_KEY twin (same label/ID) carrying CKA_EC_POINT, which OpenSSL's
// pkcs11-provider pairs with the private half to build the EVP_PKEY for certs
// and TLS. An AES key surfaces as a CKO_SECRET_KEY (CKK_AES) for wrap/unwrap
// (inc.2). Handles are 1-based indices into objTable, refreshed from the agent
// on C_FindObjectsInit.
type objInfo struct {
	name    string
	class   C.CK_OBJECT_CLASS
	keyType C.CK_KEY_TYPE
}

// secp256r1 (P-256) OID DER, the value of CKA_EC_PARAMS for EC keys.
var oidP256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

var (
	objMu    sync.Mutex
	objTable []objInfo

	// ecPointCache caches each EC key's CKA_EC_POINT value (a DER OCTET STRING
	// wrapping the uncompressed SEC1 point), fetched lazily from the agent —
	// consumers query it repeatedly per handshake and the point is immutable for
	// a key version.
	ecPointMu    sync.Mutex
	ecPointCache = map[string][]byte{}
)

func refreshObjects() C.CK_RV {
	keys, err := agentListKeys()
	if err != nil {
		return C.CKR_DEVICE_ERROR
	}
	tbl := make([]objInfo, 0, len(keys)*2)
	for _, k := range keys {
		switch k.kind() {
		case "EC":
			tbl = append(tbl,
				objInfo{name: k.Name, class: C.CKO_PRIVATE_KEY, keyType: C.CKK_EC},
				objInfo{name: k.Name, class: C.CKO_PUBLIC_KEY, keyType: C.CKK_EC})
		case "AES":
			tbl = append(tbl, objInfo{name: k.Name, class: C.CKO_SECRET_KEY, keyType: C.CKK_AES})
		}
	}
	objMu.Lock()
	objTable = tbl
	objMu.Unlock()
	return C.CKR_OK
}

// ecPointDER returns the CKA_EC_POINT value for the named key: the uncompressed
// point wrapped in a DER OCTET STRING (04 41 04 || X || Y for P-256), per the
// PKCS#11 EC key attribute spec.
func ecPointDER(name string) ([]byte, error) {
	ecPointMu.Lock()
	if v, ok := ecPointCache[name]; ok {
		ecPointMu.Unlock()
		return v, nil
	}
	ecPointMu.Unlock()
	point, err := agentPublicEC(name)
	if err != nil {
		return nil, err
	}
	der := make([]byte, 0, len(point)+2)
	der = append(der, 0x04, byte(len(point)))
	der = append(der, point...)
	ecPointMu.Lock()
	ecPointCache[name] = der
	ecPointMu.Unlock()
	return der, nil
}

func objByHandle(h uint) (objInfo, bool) {
	objMu.Lock()
	defer objMu.Unlock()
	if h < 1 || int(h) > len(objTable) {
		return objInfo{}, false
	}
	return objTable[h-1], true
}

// attrFilter is a subset of a C_FindObjects template we can match on.
type attrFilter struct {
	hasClass bool
	class    C.CK_OBJECT_CLASS
	hasType  bool
	keyType  C.CK_KEY_TYPE
	hasLabel bool
	label    string
}

func readTemplate(pTemplate C.CK_ATTRIBUTE_PTR, count C.CK_ULONG) attrFilter {
	var f attrFilter
	if pTemplate == nil || count == 0 {
		return f
	}
	attrs := unsafe.Slice((*C.CK_ATTRIBUTE)(pTemplate), int(count))
	for i := range attrs {
		a := &attrs[i]
		switch a._type {
		case C.CKA_CLASS:
			if a.ulValueLen >= C.CK_ULONG(unsafe.Sizeof(C.CK_OBJECT_CLASS(0))) && a.pValue != nil {
				f.hasClass = true
				f.class = *(*C.CK_OBJECT_CLASS)(unsafe.Pointer(a.pValue))
			}
		case C.CKA_KEY_TYPE:
			if a.ulValueLen >= C.CK_ULONG(unsafe.Sizeof(C.CK_KEY_TYPE(0))) && a.pValue != nil {
				f.hasType = true
				f.keyType = *(*C.CK_KEY_TYPE)(unsafe.Pointer(a.pValue))
			}
		case C.CKA_LABEL, C.CKA_ID:
			if a.pValue != nil && a.ulValueLen > 0 {
				f.hasLabel = true
				f.label = string(C.GoBytes(unsafe.Pointer(a.pValue), C.int(a.ulValueLen)))
			}
		}
	}
	return f
}

func (f attrFilter) matches(o objInfo) bool {
	if f.hasClass && f.class != o.class {
		return false
	}
	if f.hasType && f.keyType != o.keyType {
		return false
	}
	if f.hasLabel && f.label != o.name {
		return false
	}
	return true
}

//export C_FindObjectsInit
func C_FindObjectsInit(h C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, count C.CK_ULONG) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if rv := refreshObjects(); rv != C.CKR_OK {
		return rv
	}
	f := readTemplate(pTemplate, count)
	var matches []uint
	objMu.Lock()
	for i, o := range objTable {
		if f.matches(o) {
			matches = append(matches, uint(i+1))
		}
	}
	objMu.Unlock()
	ok := withSession(uint(h), func(s *session) {
		s.findActive = true
		s.findMatches = matches
		s.findPos = 0
	})
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

//export C_FindObjects
func C_FindObjects(h C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulObjectCount == nil || (phObject == nil && ulMaxObjectCount > 0) {
		return C.CKR_ARGUMENTS_BAD
	}
	var rv C.CK_RV = C.CKR_OK
	var n int
	ok := withSession(uint(h), func(s *session) {
		if !s.findActive {
			rv = C.CKR_OPERATION_NOT_INITIALIZED
			return
		}
		out := unsafe.Slice((*C.CK_OBJECT_HANDLE)(phObject), int(ulMaxObjectCount))
		for n < int(ulMaxObjectCount) && s.findPos < len(s.findMatches) {
			out[n] = C.CK_OBJECT_HANDLE(s.findMatches[s.findPos])
			n++
			s.findPos++
		}
	})
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if rv != C.CKR_OK {
		return rv
	}
	*pulObjectCount = C.CK_ULONG(n)
	return C.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(h C.CK_SESSION_HANDLE) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	ok := withSession(uint(h), func(s *session) {
		s.findActive = false
		s.findMatches = nil
		s.findPos = 0
	})
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

// setAttr implements the Cryptoki buffer-size protocol for one attribute.
func setAttr(a *C.CK_ATTRIBUTE, data []byte) {
	if a.pValue == nil {
		a.ulValueLen = C.CK_ULONG(len(data))
		return
	}
	if a.ulValueLen < C.CK_ULONG(len(data)) {
		a.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
		return
	}
	if len(data) > 0 {
		dst := unsafe.Slice((*byte)(unsafe.Pointer(a.pValue)), len(data))
		copy(dst, data)
	}
	a.ulValueLen = C.CK_ULONG(len(data))
}

func ulongBytes(v C.CK_ULONG) []byte {
	n := int(unsafe.Sizeof(v))
	b := make([]byte, n)
	copy(b, unsafe.Slice((*byte)(unsafe.Pointer(&v)), n))
	return b
}

//export C_GetAttributeValue
func C_GetAttributeValue(h C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, count C.CK_ULONG) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	o, ok := objByHandle(uint(hObject))
	if !ok {
		return C.CKR_OBJECT_HANDLE_INVALID
	}
	if pTemplate == nil || count == 0 {
		return C.CKR_ARGUMENTS_BAD
	}
	attrs := unsafe.Slice((*C.CK_ATTRIBUTE)(pTemplate), int(count))
	rv := C.CK_RV(C.CKR_OK)
	isEC := o.keyType == C.CKK_EC
	for i := range attrs {
		a := &attrs[i]
		switch a._type {
		case C.CKA_CLASS:
			setAttr(a, ulongBytes(C.CK_ULONG(o.class)))
		case C.CKA_KEY_TYPE:
			setAttr(a, ulongBytes(C.CK_ULONG(o.keyType)))
		case C.CKA_LABEL, C.CKA_ID:
			setAttr(a, []byte(o.name))
		case C.CKA_TOKEN:
			setAttr(a, []byte{1})
		case C.CKA_PRIVATE:
			b := byte(1)
			if o.class == C.CKO_PUBLIC_KEY {
				b = 0
			}
			setAttr(a, []byte{b})
		case C.CKA_SIGN:
			b := byte(0)
			if o.class == C.CKO_PRIVATE_KEY {
				b = 1
			}
			setAttr(a, []byte{b})
		case C.CKA_VERIFY:
			b := byte(0)
			if o.class == C.CKO_PUBLIC_KEY {
				b = 1
			}
			setAttr(a, []byte{b})
		case C.CKA_WRAP, C.CKA_UNWRAP, C.CKA_ENCRYPT, C.CKA_DECRYPT:
			b := byte(0)
			if o.class == C.CKO_SECRET_KEY {
				b = 1
			}
			setAttr(a, []byte{b})
		case C.CKA_VALUE_LEN:
			// AES-256 key length; consumers (Java SunPKCS11) size the key from it.
			if o.keyType == C.CKK_AES {
				setAttr(a, ulongBytes(32))
			} else {
				a.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
				rv = C.CKR_ATTRIBUTE_TYPE_INVALID
			}
		case C.CKA_SENSITIVE:
			// Vault key material never leaves the enclave.
			b := byte(0)
			if o.class != C.CKO_PUBLIC_KEY {
				b = 1
			}
			setAttr(a, []byte{b})
		case C.CKA_EXTRACTABLE, C.CKA_ALWAYS_AUTHENTICATE, C.CKA_MODIFIABLE:
			setAttr(a, []byte{0})
		case C.CKA_EC_PARAMS:
			if isEC {
				setAttr(a, oidP256)
			} else {
				a.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
				rv = C.CKR_ATTRIBUTE_TYPE_INVALID
			}
		case C.CKA_EC_POINT:
			if isEC {
				der, err := ecPointDER(o.name)
				if err != nil {
					a.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
					rv = C.CKR_ATTRIBUTE_TYPE_INVALID
					break
				}
				setAttr(a, der)
			} else {
				a.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
				rv = C.CKR_ATTRIBUTE_TYPE_INVALID
			}
		default:
			a.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
			rv = C.CKR_ATTRIBUTE_TYPE_INVALID
		}
	}
	return rv
}
