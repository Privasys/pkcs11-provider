# Security Policy

## Reporting a Vulnerability

We take security seriously at Privasys. If you discover a vulnerability in the
Privasys PKCS#11 provider, please report it responsibly through one of the
following channels:

- **Email:** [security@privasys.org](mailto:security@privasys.org)
- **GitHub:** Open a [private security advisory](https://github.com/Privasys/pkcs11-provider/security/advisories/new)

Please do not open public issues for security vulnerabilities.

## Trust model / scope

This module is a **thin Cryptoki front-end**: it holds **no key material and no
vault session**. Keys live in the attested vault constellation and are used
**in-enclave**; the module only proxies the consumption ops to the local
`privasys vault serve` agent, which owns the RA-TLS holder-of-key session. The
platform control plane is never in the key data path.

In scope for this repo: transport, memory-safety, and ABI-correctness issues in
the module itself. The vault/agent attestation and policy trust model is part of
the platform; report those through the same channels.
