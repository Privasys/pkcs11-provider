/* The Cryptoki entry point. C_GetFunctionList hands back a CK_FUNCTION_LIST
 * whose pointers are the Go //export'd implementations. The PKCS#11 spec
 * requires EVERY slot to be non-NULL (consumers like OpenSSL's pkcs11-provider
 * call through the list without NULL checks), so unimplemented functions get
 * PRV_* stubs returning the spec-appropriate "not supported" code.
 * Order: include cryptoki.h (the CK types) FIRST, then _cgo_export.h (the Go
 * function declarations, which reference those types). */
#include "cryptoki.h"
#include "_cgo_export.h"

/* Not-supported stubs (exact pkcs11f.h prototypes). */
static CK_RV PRV_C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) { return CKR_STATE_UNSAVEABLE; }
static CK_RV PRV_C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) { return CKR_SAVED_STATE_INVALID; }
static CK_RV PRV_C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) { return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV PRV_C_GetFunctionStatus(CK_SESSION_HANDLE hSession) { return CKR_FUNCTION_NOT_PARALLEL; }
static CK_RV PRV_C_CancelFunction(CK_SESSION_HANDLE hSession) { return CKR_FUNCTION_NOT_PARALLEL; }
static CK_RV PRV_C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved) { return CKR_NO_EVENT; }

static CK_FUNCTION_LIST functionList = {
    {2, 40}, /* this list reports Cryptoki 2.40; C_GetInfo reports 3.1 */
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = PRV_C_InitToken,
    .C_InitPIN = PRV_C_InitPIN,
    .C_SetPIN = PRV_C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = PRV_C_GetOperationState,
    .C_SetOperationState = PRV_C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = PRV_C_CreateObject,
    .C_CopyObject = PRV_C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = PRV_C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = PRV_C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = PRV_C_EncryptInit,
    .C_Encrypt = PRV_C_Encrypt,
    .C_EncryptUpdate = PRV_C_EncryptUpdate,
    .C_EncryptFinal = PRV_C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = PRV_C_DecryptUpdate,
    .C_DecryptFinal = PRV_C_DecryptFinal,
    .C_DigestInit = PRV_C_DigestInit,
    .C_Digest = PRV_C_Digest,
    .C_DigestUpdate = PRV_C_DigestUpdate,
    .C_DigestKey = PRV_C_DigestKey,
    .C_DigestFinal = PRV_C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = PRV_C_SignRecoverInit,
    .C_SignRecover = PRV_C_SignRecover,
    .C_VerifyInit = PRV_C_VerifyInit,
    .C_Verify = PRV_C_Verify,
    .C_VerifyUpdate = PRV_C_VerifyUpdate,
    .C_VerifyFinal = PRV_C_VerifyFinal,
    .C_VerifyRecoverInit = PRV_C_VerifyRecoverInit,
    .C_VerifyRecover = PRV_C_VerifyRecover,
    .C_DigestEncryptUpdate = PRV_C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = PRV_C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = PRV_C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = PRV_C_DecryptVerifyUpdate,
    .C_GenerateKey = PRV_C_GenerateKey,
    .C_GenerateKeyPair = PRV_C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = PRV_C_UnwrapKey,
    .C_DeriveKey = PRV_C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = PRV_C_GetFunctionStatus,
    .C_CancelFunction = PRV_C_CancelFunction,
    .C_WaitForSlotEvent = PRV_C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  if (ppFunctionList == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  *ppFunctionList = &functionList;
  return CKR_OK;
}
