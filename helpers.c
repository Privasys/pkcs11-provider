#include "helpers.h"

/* Copy src into the n-byte Cryptoki field dst, space-padded, NOT NUL-terminated
 * (Cryptoki fixed fields are blank-padded). */
static void ckpad(CK_UTF8CHAR_PTR dst, size_t n, const char *src) {
  size_t l = src ? strlen(src) : 0;
  size_t i;
  for (i = 0; i < n; i++) {
    dst[i] = (CK_UTF8CHAR)(i < l ? src[i] : ' ');
  }
}

void privasys_fill_info(CK_INFO_PTR p) {
  memset(p, 0, sizeof(*p));
  p->cryptokiVersion.major = 3;
  p->cryptokiVersion.minor = 1;
  ckpad(p->manufacturerID, sizeof(p->manufacturerID), "Privasys");
  p->flags = 0;
  ckpad(p->libraryDescription, sizeof(p->libraryDescription), "Privasys vHSM PKCS#11");
  p->libraryVersion.major = 0;
  p->libraryVersion.minor = 1;
}

void privasys_fill_slot_info(CK_SLOT_INFO_PTR p) {
  memset(p, 0, sizeof(*p));
  ckpad(p->slotDescription, sizeof(p->slotDescription),
        "Privasys attested vault constellation");
  ckpad(p->manufacturerID, sizeof(p->manufacturerID), "Privasys");
  /* A token is always present (the vault); the slot is not removable. */
  p->flags = CKF_TOKEN_PRESENT;
  p->hardwareVersion.major = 0;
  p->hardwareVersion.minor = 1;
  p->firmwareVersion.major = 0;
  p->firmwareVersion.minor = 1;
}

void privasys_fill_token_info(CK_TOKEN_INFO_PTR p, const char *label) {
  memset(p, 0, sizeof(*p));
  ckpad(p->label, sizeof(p->label), (label && *label) ? label : "Privasys Vault");
  ckpad(p->manufacturerID, sizeof(p->manufacturerID), "Privasys");
  ckpad(p->model, sizeof(p->model), "vHSM");
  ckpad(p->serialNumber, sizeof(p->serialNumber), "0");
  /* Keys live in the attested constellation; the holder-of-key session is
   * established out of band by the CLI/agent, so the token presents as
   * already-initialised and login-not-required for the consumption surface. */
  p->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
  p->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  p->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
  p->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  p->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
  p->ulMaxPinLen = 256;
  p->ulMinPinLen = 0;
  p->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  p->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  p->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  p->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  p->hardwareVersion.major = 0;
  p->hardwareVersion.minor = 1;
  p->firmwareVersion.major = 0;
  p->firmwareVersion.minor = 1;
}
