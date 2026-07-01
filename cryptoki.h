/* Platform wrapper that defines the five Cryptoki macros (UNIX/Linux, natural
 * struct alignment — Linux PKCS#11 modules do NOT 1-byte-pack) and pulls in the
 * authoritative OASIS PKCS#11 3.1 headers. Include THIS, never pkcs11.h directly.
 */
#ifndef PRIVASYS_CRYPTOKI_H
#define PRIVASYS_CRYPTOKI_H

#include <string.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#include "pkcs11.h"

#endif /* PRIVASYS_CRYPTOKI_H */
