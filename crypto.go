package main

/*
#include "cryptoki.h"
*/
import "C"

import "unsafe"

// gcmIV extracts the IV from a CKM_AES_GCM mechanism's CK_GCM_PARAMS.
func gcmIV(pMechanism C.CK_MECHANISM_PTR) ([]byte, bool) {
	if pMechanism == nil || pMechanism.pParameter == nil {
		return nil, false
	}
	if pMechanism.ulParameterLen < C.CK_ULONG(unsafe.Sizeof(C.CK_GCM_PARAMS{})) {
		return nil, false
	}
	p := (*C.CK_GCM_PARAMS)(unsafe.Pointer(pMechanism.pParameter))
	if p.pIv == nil || p.ulIvLen == 0 {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(p.pIv), C.int(p.ulIvLen)), true
}

//export C_DecryptInit
func C_DecryptInit(h C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	o, ok := objByHandle(uint(hKey))
	if !ok {
		return C.CKR_KEY_HANDLE_INVALID
	}
	if o.class != C.CKO_SECRET_KEY || o.keyType != C.CKK_AES {
		return C.CKR_KEY_TYPE_INCONSISTENT
	}
	if pMechanism.mechanism != C.CKM_AES_GCM {
		return C.CKR_MECHANISM_INVALID
	}
	iv, ok := gcmIV(pMechanism)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}
	if !withSession(uint(h), func(s *session) {
		s.decryptKey = uint(hKey)
		s.decryptIV = iv
	}) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

//export C_Decrypt
func C_Decrypt(h C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	var keyHandle uint
	var iv []byte
	rv := C.CK_RV(C.CKR_OK)
	if !withSession(uint(h), func(s *session) {
		if s.decryptKey == 0 {
			rv = C.CKR_OPERATION_NOT_INITIALIZED
			return
		}
		keyHandle = s.decryptKey
		iv = s.decryptIV
	}) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if rv != C.CKR_OK {
		return rv
	}

	// Length query: the plaintext is at most the ciphertext length (GCM strips
	// the tag), a valid upper bound — no agent round-trip needed.
	if pData == nil {
		*pulDataLen = ulEncryptedDataLen
		return C.CKR_OK
	}

	o, ok := objByHandle(keyHandle)
	if !ok {
		return C.CKR_KEY_HANDLE_INVALID
	}
	var ct []byte
	if pEncryptedData != nil && ulEncryptedDataLen > 0 {
		ct = C.GoBytes(unsafe.Pointer(pEncryptedData), C.int(ulEncryptedDataLen))
	}
	pt, err := agentUnwrap(o.name, ct, iv)
	if err != nil {
		return C.CKR_FUNCTION_FAILED
	}
	if *pulDataLen < C.CK_ULONG(len(pt)) {
		*pulDataLen = C.CK_ULONG(len(pt))
		return C.CKR_BUFFER_TOO_SMALL
	}
	if len(pt) > 0 {
		dst := unsafe.Slice((*byte)(unsafe.Pointer(pData)), len(pt))
		copy(dst, pt)
	}
	*pulDataLen = C.CK_ULONG(len(pt))
	withSession(uint(h), func(s *session) { s.decryptKey = 0; s.decryptIV = nil })
	return C.CKR_OK
}

// C_WrapKey fails closed: vault keys are non-extractable — the key material
// never leaves the enclave, which is the whole point. (Key transport of external
// material stays in the native API.)
//
//export C_WrapKey
func C_WrapKey(h C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if _, ok := objByHandle(uint(hKey)); !ok {
		return C.CKR_KEY_HANDLE_INVALID
	}
	return C.CKR_KEY_UNEXTRACTABLE
}

//export C_DestroyObject
func C_DestroyObject(h C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV {
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
	if err := agentDestroy(o.name); err != nil {
		return C.CKR_FUNCTION_FAILED
	}
	return C.CKR_OK
}
