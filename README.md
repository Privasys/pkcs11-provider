# pkcs11-provider

A **PKCS#11 3.1 (Cryptoki) provider module** for the Privasys vHSM. Load it into
any application that speaks PKCS#11 — OpenSSL (`pkcs11-provider`), Java
(SunPKCS11), nginx/Apache/HAProxy TLS, code-signing tools, database TDE — and it
uses keys held in the **attested vault constellation**, with no application change
and **no key material on the host**.

This is the "standard skin, novel core" pattern (see the vHSM plan): a familiar
Cryptoki C ABI in front of the attested-policy vault.

## Architecture — thin module + agent

The `.so` is a **cgo `-buildmode=c-shared` module built with the Go standard
library only** (no RA-TLS fork, no vault crypto in the module). It translates the
Cryptoki C ABI into calls on the local **`privasys vault serve` agent**, which
holds the RA-TLS holder-of-key session to the constellation and does the actual
crypto **in-enclave**. So:

- the **data plane stays direct** (agent ↔ vault RA-TLS; the platform is never in
  the key path),
- the module carries **no secrets**, and
- `C_Login` **attaches to the agent's session** rather than overloading the PIN
  with a real grant (the plan's decision).

```
app ──(PKCS#11 C ABI)──▶ libprivasys_pkcs11.so ──(localhost REST)──▶ privasys vault serve ──(RA-TLS)──▶ vault constellation
```

- **Token = a vault.** One slot/token, fronting the vault the agent serves.
- **Object = a vault key.** `GET /keys` → `C_FindObjects`. An EC signing key is a
  `CKO_PRIVATE_KEY`/`CKK_EC` object; an AES key is a `CKO_SECRET_KEY`/`CKK_AES`.

## Scope: consumption, not management

By design the module lets existing apps **use** keys; key **creation and policy**
stay in the native API (the CLI / Azure-REST facade / KMIP), because PKCS#11
cannot express attested-measurement principals, WebAuthn step-up, or policy
authoring. Step-up-gated ops **fail closed** over PKCS#11.

Implemented: `C_Initialize`/`Finalize`, `C_GetInfo`, slot/token info, mechanism
list, sessions, `C_Login` (session-attach), `C_FindObjects*` (each EC key
surfaces as a private key **plus a public-key twin** carrying `CKA_EC_POINT`),
`C_GetAttributeValue`, `C_SignInit`/`C_Sign` and the streaming
`C_SignUpdate`/`C_SignFinal`, `C_Encrypt`/`C_Decrypt` (AES-GCM via the agent
`wrapKey`/`unwrapKey` — the caller supplies the 12-byte GCM nonce and owns its
per-key uniqueness), `C_DestroyObject`, `C_GenerateRandom` (host CSPRNG —
local nonces, not vault material). Every remaining `CK_FUNCTION_LIST` slot is a
spec-appropriate not-supported stub — the list is complete, as the spec
requires (consumers call through it without NULL checks).

### Java (SunPKCS11)

Vault AES keys surface as standalone `KeyStore` aliases (EC private keys need
certificate objects Java-side, which the module does not serve yet), and
`Cipher AES/GCM/NoPadding` drives the vault encrypt/decrypt:

```
printf 'name = PrivasysVault\nlibrary = /path/to/libprivasys_pkcs11.so\n' > p11.cfg
PRIVASYS_PKCS11_VAULT=<vault-id> java tools/P11Aes.java p11.cfg
```

### Signing

`CKM_ECDSA_SHA256` signs a message (the vault hashes, ECDSA-P256-SHA256) and
`CKM_ECDSA` signs a **pre-computed digest** (what TLS and most code-signers
use) via the vault's raw/pre-hashed sign mode. Both return raw `r‖s`, exactly
what PKCS#11 expects.

### OpenSSL (`pkcs11-provider`)

The module works under OpenSSL 3.x with the
[pkcs11-provider](https://github.com/latchset/pkcs11-provider):

```
export PKCS11_PROVIDER_MODULE=/path/to/libprivasys_pkcs11.so
export PRIVASYS_PKCS11_VAULT=<vault-id>          # privasys vault serve is running
# mint a cert whose key lives in the vault
openssl req -new -x509 -provider pkcs11 -provider default \
  -key "pkcs11:object=<key-name>;type=private" -subj "/CN=example" -out cert.pem
# serve TLS with the vault-held key (the handshake signature happens in-enclave)
openssl s_server -provider pkcs11 -provider default \
  -key "pkcs11:object=<key-name>;type=private" -cert cert.pem -accept 4443 -www
```

## Build & test

```
make            # builds libprivasys_pkcs11.so (CGO_ENABLED=1, -buildmode=c-shared)
make test       # pkcs11-tool --list-slots (needs opensc)
cc test_harness.c -ldl -o harness && ./harness ./libprivasys_pkcs11.so   # ABI smoke test, no opensc
```

Config (env): `PRIVASYS_PKCS11_AGENT` (agent base URL, default
`http://127.0.0.1:8200`), `PRIVASYS_PKCS11_VAULT` (token label = the vault id).

The Cryptoki headers (`pkcs11.h`, `pkcs11t.h`, `pkcs11f.h`) are the authoritative
OASIS PKCS#11 3.1 headers.

## Licence

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
