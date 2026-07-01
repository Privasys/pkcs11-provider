/* Standalone ABI smoke test: dlopen the module, walk the loadable-token path
 * through the real CK_FUNCTION_LIST. No opensc needed.
 *   cc test_harness.c -ldl -o harness && PRIVASYS_PKCS11_VAULT=v ./harness ./libprivasys_pkcs11.so
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "cryptoki.h"

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <module.so>\n", argv[0]); return 2; }
  void *h = dlopen(argv[1], RTLD_NOW);
  if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }

  CK_RV (*getList)(CK_FUNCTION_LIST_PTR_PTR) = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(h, "C_GetFunctionList");
  if (!getList) { fprintf(stderr, "no C_GetFunctionList\n"); return 1; }

  CK_FUNCTION_LIST_PTR fl = NULL;
  CK_RV rv = getList(&fl);
  printf("C_GetFunctionList  rv=0x%08lx  listVersion=%d.%d\n", rv, fl->version.major, fl->version.minor);

  rv = fl->C_Initialize(NULL_PTR);
  printf("C_Initialize       rv=0x%08lx\n", rv);

  CK_INFO info; memset(&info, 0, sizeof info);
  rv = fl->C_GetInfo(&info);
  printf("C_GetInfo          rv=0x%08lx  cryptoki=%d.%d\n", rv, info.cryptokiVersion.major, info.cryptokiVersion.minor);

  CK_SLOT_ID slots[8]; CK_ULONG n = 8;
  rv = fl->C_GetSlotList(CK_TRUE, slots, &n);
  printf("C_GetSlotList      rv=0x%08lx  count=%lu  slot0=%lu\n", rv, (unsigned long)n, n ? (unsigned long)slots[0] : 0);

  CK_TOKEN_INFO ti; memset(&ti, 0, sizeof ti);
  rv = fl->C_GetTokenInfo(slots[0], &ti);
  char label[33]; memcpy(label, ti.label, 32); label[32] = 0;
  int e = 32; while (e > 0 && label[e-1] == ' ') label[--e] = 0;
  printf("C_GetTokenInfo     rv=0x%08lx  label='%s'\n", rv, label);

  CK_MECHANISM_TYPE mechs[16]; CK_ULONG mn = 16;
  rv = fl->C_GetMechanismList(slots[0], mechs, &mn);
  printf("C_GetMechanismList rv=0x%08lx  count=%lu\n", rv, (unsigned long)mn);

  CK_SESSION_HANDLE sess = 0;
  rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
  printf("C_OpenSession      rv=0x%08lx  handle=%lu\n", rv, (unsigned long)sess);

  rv = fl->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"", 0);
  printf("C_Login            rv=0x%08lx\n", rv);

  /* Find EC private-key objects (backed by the agent's GET /keys). */
  CK_OBJECT_CLASS priv = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &priv, sizeof priv}};
  rv = fl->C_FindObjectsInit(sess, tmpl, 1);
  printf("C_FindObjectsInit  rv=0x%08lx\n", rv);
  CK_OBJECT_HANDLE objs[8]; CK_ULONG on = 0;
  rv = fl->C_FindObjects(sess, objs, 8, &on);
  printf("C_FindObjects      rv=0x%08lx  count=%lu\n", rv, (unsigned long)on);
  fl->C_FindObjectsFinal(sess);

  if (on > 0) {
    char klabel[64] = {0};
    CK_ATTRIBUTE la[] = {{CKA_LABEL, klabel, sizeof klabel - 1}};
    rv = fl->C_GetAttributeValue(sess, objs[0], la, 1);
    printf("C_GetAttributeValue rv=0x%08lx label='%s'\n", rv, klabel);

    CK_MECHANISM mech = {CKM_ECDSA_SHA256, NULL_PTR, 0};
    rv = fl->C_SignInit(sess, &mech, objs[0]);
    printf("C_SignInit         rv=0x%08lx\n", rv);
    CK_BYTE data[] = "hello world";
    CK_BYTE sig[128]; CK_ULONG siglen = sizeof sig;
    rv = fl->C_Sign(sess, data, sizeof data - 1, sig, &siglen);
    printf("C_Sign             rv=0x%08lx  siglen=%lu\n", rv, (unsigned long)siglen);
  }

  /* Find AES secret keys -> Decrypt (agent unwrapKey) + Destroy (agent DELETE). */
  CK_OBJECT_CLASS sec = CKO_SECRET_KEY;
  CK_ATTRIBUTE tmpl2[] = {{CKA_CLASS, &sec, sizeof sec}};
  fl->C_FindObjectsInit(sess, tmpl2, 1);
  CK_OBJECT_HANDLE aesobjs[8]; CK_ULONG an = 0;
  fl->C_FindObjects(sess, aesobjs, 8, &an);
  fl->C_FindObjectsFinal(sess);
  printf("AES keys found     count=%lu\n", (unsigned long)an);
  if (an > 0) {
    CK_BYTE iv[12] = {0};
    CK_GCM_PARAMS gcm = {iv, sizeof iv, 96, NULL_PTR, 0, 128};
    CK_MECHANISM dm = {CKM_AES_GCM, &gcm, sizeof gcm};
    rv = fl->C_DecryptInit(sess, &dm, aesobjs[0]);
    printf("C_DecryptInit      rv=0x%08lx\n", rv);
    CK_BYTE ctin[] = "ciphertext-bytes-here";
    CK_BYTE out[64]; CK_ULONG outlen = sizeof out;
    rv = fl->C_Decrypt(sess, ctin, sizeof ctin - 1, out, &outlen);
    out[outlen < sizeof out ? outlen : sizeof out - 1] = 0;
    printf("C_Decrypt          rv=0x%08lx  outlen=%lu  pt='%s'\n", rv, (unsigned long)outlen, out);
    rv = fl->C_DestroyObject(sess, aesobjs[0]);
    printf("C_DestroyObject    rv=0x%08lx\n", rv);
  }

  rv = fl->C_CloseSession(sess);
  printf("C_CloseSession     rv=0x%08lx\n", rv);

  fl->C_Finalize(NULL_PTR);
  printf("DONE\n");
  return 0;
}
