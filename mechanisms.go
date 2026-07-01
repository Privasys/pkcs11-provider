package main

/*
#include "cryptoki.h"
*/
import "C"

import "unsafe"

// supportedMechanisms is the consumption surface the agent backs:
//   - CKM_ECDSA_SHA256: sign a message (the vault hashes — works today).
//   - CKM_ECDSA:        sign a pre-computed digest (needs the vault raw/pre-hashed
//     sign mode; advertised so TLS stacks discover it, but Sign fails closed until
//     the vault supports it — see the Phase 4 dependency note).
//   - CKM_AES_GCM:      wrap/unwrap (AES-256-GCM) for key transport / decrypt.
func supportedMechanisms() []C.CK_MECHANISM_TYPE {
	return []C.CK_MECHANISM_TYPE{
		C.CKM_ECDSA,
		C.CKM_ECDSA_SHA256,
		C.CKM_AES_GCM,
	}
}

func writeMechanismList(pList C.CK_MECHANISM_TYPE_PTR, mechs []C.CK_MECHANISM_TYPE) {
	dst := unsafe.Slice((*C.CK_MECHANISM_TYPE)(pList), len(mechs))
	copy(dst, mechs)
}

func fillMechanismInfo(mechType C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	switch mechType {
	case C.CKM_ECDSA, C.CKM_ECDSA_SHA256:
		pInfo.ulMinKeySize = 256
		pInfo.ulMaxKeySize = 256
		pInfo.flags = C.CKF_SIGN | C.CKF_EC_F_P | C.CKF_EC_NAMEDCURVE
		return C.CKR_OK
	case C.CKM_AES_GCM:
		pInfo.ulMinKeySize = 256
		pInfo.ulMaxKeySize = 256
		pInfo.flags = C.CKF_WRAP | C.CKF_UNWRAP | C.CKF_ENCRYPT | C.CKF_DECRYPT
		return C.CKR_OK
	default:
		return C.CKR_MECHANISM_INVALID
	}
}
