# Contributing

Thanks for your interest in the Privasys PKCS#11 provider.

## Licence & sign-off

This project is licensed under the **GNU Affero General Public License v3.0**
(see [LICENSE](LICENSE)). By contributing you agree that your contributions are
licensed under the same terms. Please sign off your commits (`git commit -s`) to
certify the [Developer Certificate of Origin](https://developercertificate.org/).

## Building & testing

Requires Go 1.25+ and a C toolchain (cgo).

```
make            # builds libprivasys_pkcs11.so
make test       # pkcs11-tool --list-slots (needs opensc)
cc test_harness.c -ldl -o harness && ./harness ./libprivasys_pkcs11.so   # ABI smoke test
```

## Scope (please read before a PR)

This module is deliberately **consumption, not management**: it lets existing
PKCS#11 applications *use* attested vault keys. Key creation, policy authoring,
and step-up stay in the native API (the CLI / Azure-REST facade / KMIP), because
PKCS#11 cannot express attested-measurement principals or WebAuthn step-up.

- **Welcome:** more consumption mechanisms (additional Sign/Decrypt algorithms),
  OpenSSL `pkcs11-provider` / Java (SunPKCS11) interop, robustness fixes.
- **Out of scope by design:** authoring policy over PKCS#11, or moving key
  material out of the enclave (`C_WrapKey` of a vault key stays
  `CKR_KEY_UNEXTRACTABLE`).

## Style

Match the surrounding code. Keep the module **thin** — Go standard library only,
no vault crypto and no RA-TLS in the module; the agent does that. The fiddly
fixed-size Cryptoki structs stay in the C helpers, not in Go.
