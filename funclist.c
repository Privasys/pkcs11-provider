/* The Cryptoki entry point. C_GetFunctionList hands back a CK_FUNCTION_LIST
 * whose pointers are the Go //export'd implementations. Unimplemented slots stay
 * NULL (designated initialisers); callers test for NULL on optional functions.
 * Order: include cryptoki.h (the CK types) FIRST, then _cgo_export.h (the Go
 * function declarations, which reference those types). */
#include "cryptoki.h"
#include "_cgo_export.h"

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
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  if (ppFunctionList == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  *ppFunctionList = &functionList;
  return CKR_OK;
}
