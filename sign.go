package main

/*
#include "cryptoki.h"
*/
import "C"

import "unsafe"

// p256SigLen is the raw r||s ECDSA signature length for P-256 (what CKM_ECDSA*
// returns and what the agent's ES256 signature already is).
const p256SigLen = 64

//export C_SignInit
func C_SignInit(h C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
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
	if o.class != C.CKO_PRIVATE_KEY || o.keyType != C.CKK_EC {
		return C.CKR_KEY_TYPE_INCONSISTENT
	}
	mech := pMechanism.mechanism
	switch mech {
	case C.CKM_ECDSA_SHA256:
		// message-sign: the vault hashes (ECDSA-P256-SHA256). Supported today.
	case C.CKM_ECDSA:
		// pre-hashed digest sign: needs a raw/pre-hashed vault sign mode; fail
		// closed until then (Phase 4 dependency) rather than double-hash.
		return C.CKR_FUNCTION_NOT_SUPPORTED
	default:
		return C.CKR_MECHANISM_INVALID
	}
	ok = withSession(uint(h), func(s *session) {
		s.signKey = uint(hKey)
		s.signMech = uint(mech)
	})
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

//export C_Sign
func C_Sign(h C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	var keyHandle uint
	rv := C.CK_RV(C.CKR_OK)
	ok := withSession(uint(h), func(s *session) {
		if s.signKey == 0 {
			rv = C.CKR_OPERATION_NOT_INITIALIZED
			return
		}
		keyHandle = s.signKey
	})
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if rv != C.CKR_OK {
		return rv
	}

	// Length query.
	if pSignature == nil {
		*pulSignatureLen = p256SigLen
		return C.CKR_OK
	}
	if *pulSignatureLen < p256SigLen {
		*pulSignatureLen = p256SigLen
		return C.CKR_BUFFER_TOO_SMALL
	}

	o, ok := objByHandle(keyHandle)
	if !ok {
		return C.CKR_KEY_HANDLE_INVALID
	}
	var msg []byte
	if pData != nil && ulDataLen > 0 {
		msg = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}
	sig, err := agentSign(o.name, "ES256", msg)
	if err != nil {
		return C.CKR_FUNCTION_FAILED
	}
	if len(sig) != p256SigLen {
		return C.CKR_FUNCTION_FAILED
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(pSignature)), p256SigLen)
	copy(dst, sig)
	*pulSignatureLen = p256SigLen

	// One-shot: clear the operation.
	withSession(uint(h), func(s *session) { s.signKey = 0; s.signMech = 0 })
	return C.CKR_OK
}
