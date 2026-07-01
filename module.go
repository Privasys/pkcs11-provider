// Privasys PKCS#11 provider — a thin Cryptoki (PKCS#11 3.1) module that
// translates the C ABI into calls on the local `privasys vault serve` agent,
// which holds the RA-TLS holder-of-key session to the vault constellation. The
// module embeds no key material and no vault crypto: one token == one vault, one
// object == one vault key, and the consumption ops (Sign/Decrypt/Wrap/Unwrap)
// proxy to the agent. See the README for the architecture and scope.
package main

/*
#include <stdlib.h>
#include "cryptoki.h"
#include "helpers.h"
*/
import "C"

import (
	"crypto/rand"
	"os"
	"sync"
	"unsafe"
)

func main() {} // required for -buildmode=c-shared; never called.

// One slot/token, fronting the agent's configured vault.
const slotID = 1

var (
	stateMu sync.Mutex
	inited  bool
)

func isInited() bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	return inited
}

// tokenLabel is the PKCS#11 token label: the vault id the agent fronts, so
// `pkcs11-tool --list-slots` shows which vault this token is.
func tokenLabel() string {
	if v := os.Getenv("PRIVASYS_PKCS11_VAULT"); v != "" {
		return v
	}
	return "Privasys Vault"
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	stateMu.Lock()
	defer stateMu.Unlock()
	if inited {
		return C.CKR_CRYPTOKI_ALREADY_INITIALIZED
	}
	inited = true
	return C.CKR_OK
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	stateMu.Lock()
	defer stateMu.Unlock()
	if !inited {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	inited = false
	sessionsReset()
	return C.CKR_OK
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	C.privasys_fill_info(pInfo)
	return C.CKR_OK
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pSlotList == nil {
		*pulCount = 1
		return C.CKR_OK
	}
	if *pulCount < 1 {
		*pulCount = 1
		return C.CKR_BUFFER_TOO_SMALL
	}
	*pSlotList = C.CK_SLOT_ID(slotID)
	*pulCount = 1
	return C.CKR_OK
}

//export C_GetSlotInfo
func C_GetSlotInfo(id C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if id != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	C.privasys_fill_slot_info(pInfo)
	return C.CKR_OK
}

//export C_GetTokenInfo
func C_GetTokenInfo(id C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if id != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	clabel := C.CString(tokenLabel())
	C.privasys_fill_token_info(pInfo, clabel)
	C.free(unsafe.Pointer(clabel))
	return C.CKR_OK
}

//export C_GetMechanismList
func C_GetMechanismList(id C.CK_SLOT_ID, pList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if id != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mechs := supportedMechanisms()
	n := C.CK_ULONG(len(mechs))
	if pList == nil {
		*pulCount = n
		return C.CKR_OK
	}
	if *pulCount < n {
		*pulCount = n
		return C.CKR_BUFFER_TOO_SMALL
	}
	writeMechanismList(pList, mechs)
	*pulCount = n
	return C.CKR_OK
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(id C.CK_SLOT_ID, mechType C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if id != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	return fillMechanismInfo(mechType, pInfo)
}

//export C_OpenSession
func C_OpenSession(id C.CK_SLOT_ID, flags C.CK_FLAGS, pApp C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if id != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if flags&C.CKF_SERIAL_SESSION == 0 {
		return C.CKR_SESSION_PARALLEL_NOT_SUPPORTED
	}
	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	*phSession = C.CK_SESSION_HANDLE(sessionOpen())
	return C.CKR_OK
}

//export C_CloseSession
func C_CloseSession(h C.CK_SESSION_HANDLE) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionClose(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

//export C_CloseAllSessions
func C_CloseAllSessions(id C.CK_SLOT_ID) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if id != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	sessionsReset()
	return C.CKR_OK
}

//export C_GetSessionInfo
func C_GetSessionInfo(h C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	pInfo.slotID = C.CK_SLOT_ID(slotID)
	pInfo.state = C.CKS_RO_USER_FUNCTIONS
	pInfo.flags = C.CKF_SERIAL_SESSION
	pInfo.ulDeviceError = 0
	return C.CKR_OK
}

// C_Login is a no-op success: the holder-of-key session to the vault is
// established out of band by the CLI/agent (the plan's decision — the PIN is not
// overloaded with a real grant). The consumption surface is authorised by the
// agent's session, so login always "succeeds" and the agent enforces policy.
//
//export C_Login
func C_Login(h C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

//export C_Logout
func C_Logout(h C.CK_SESSION_HANDLE) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_OK
}

// C_GenerateRandom serves the host CSPRNG (Go crypto/rand). Consumers like
// OpenSSL's pkcs11-provider use the token as a RAND source for local nonces;
// this is not vault key material and needs no enclave round-trip.
//
//export C_GenerateRandom
func C_GenerateRandom(h C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if pRandomData == nil && ulRandomLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}
	if ulRandomLen == 0 {
		return C.CKR_OK
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(pRandomData)), int(ulRandomLen))
	if _, err := rand.Read(buf); err != nil {
		return C.CKR_FUNCTION_FAILED
	}
	return C.CKR_OK
}

//export C_SeedRandom
func C_SeedRandom(h C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) C.CK_RV {
	if !isInited() {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if !sessionValid(uint(h)) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	return C.CKR_RANDOM_SEED_NOT_SUPPORTED
}
