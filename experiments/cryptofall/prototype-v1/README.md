# WolfTrap CRYPTOFALL — WT-CRYPTO-001

Version 0.1.0a1 | 2026-11-25 | STANDALONE LAB / NO EXECUTION AUTHORITY

## Reproduce

Linux, Python 3.11+, distribution OpenSSL 3.5+ at `/usr/bin/openssl`, with the default provider supporting Ed25519 and ML-DSA-65. No pip packages, credentials, network, or existing keys needed.

```sh
openssl version
python3 -m unittest -v
sha256sum -c SHA256SUMS
```

The test runner creates four disposable keypairs in a temporary directory, signs bounded claims, verifies real signatures with OpenSSL, and removes the temporary directory on cleanup. Tests 23–24 deliberately simulate backend unavailability/timeout; no signature success is mocked. The 33 recorded passing tests are local observations, not independent certification. A failed setup is a failure, not a skip. No code executes a protected effect.

## Trust model

This is a standalone in-memory evidence evaluator, NOT a runtime authorization gate. It consumes a caller-provisioned immutable policy, trusted time, exact active epoch, expected request identifier, and expected effect digest. The two roles (owner, witness) are distinct key slots, NOT independently controlled humans. The hybrid profile requires both Ed25519 and ML-DSA-65 signatures from each role, over a domain-separated, canonical claim and its role/algorithm/key slot. A second explicitly provisioned PQ-only policy demonstrates removal of classical verification. Untrusted claims cannot select the profile. A revoked required key or algorithm fails closed; no automatic fallback. Unknown algorithms and invalid DER shapes are denied. Signature evidence is accepted only within a maximum 30-second interval, measured by the trusted caller's clock. Both policy and claim use SHA-256 for binding in this lab; the hash is also a cryptographic dependency.

`EVIDENCE_ACCEPTED` means only that the required cryptographic assertions verified under the supplied trusted inputs. It is NOT an owner grant or approval, does not attest separate custody, does not authenticate a policy transition, and cannot invoke an effect. Repeated evidence verification is permitted and tested; replay fencing for execution belongs at the native protected-effect gate.

## Explicit limitations / production BLOCK

- The policy, active epoch and trusted clock are external trust inputs. There is no durable epoch state, rollback-resistant witness, transition authorization, monotonic revocation enforcement or emergency recovery ceremony. An authorized or compromised caller can supply another policy; even a same-epoch newly signed policy would be accepted if provisioned by the caller. This is a critical integration prerequisite, not a solved problem.
- No actual human owner approval, independent custody, hardware-backed keys or production key material. Keys and runtime share one lab host; separate algorithms do not imply independent implementations. No guarantee against a shared backend compromise.
- OpenSSL executable, libraries and provider are assumed trusted. No executable provenance, FIPS module validation, constant-time qualification or independent known-answer test suite. Key DER format is restricted to observed exact canonical prefixes and lengths. Sign/verify on one backend is not independent algorithm conformance.
- The API accepts Python objects from a trusted adapter; no hostile wire parser, streaming input bounds, concurrency snapshot/locking, durable storage, state distribution, trusted timestamping, external witness or resource-exhaustion qualification. No claim of robustness against arbitrary Python objects or concurrent mutation.
- No integration with WolfTrap, WolfAlibi, WolfChat or HERCULES has been executed. No repository writes, live signatures, deployments or effects. No migration of historical evidence, key establishment (ML-KEM), or encrypted messaging compatibility tested. No claim that cryptographic break rumors are true.

## Repository reconnaissance (read-only)

- Canonical repository moved to Bropdrop/WolfTrap; main's pyproject reports version 0.5.3 and no mandatory dependencies: https://github.com/Bropdrop/WolfTrap/blob/main/pyproject.toml
- Main README defines static review / synthetic verification / inconclusive evidence boundaries: https://github.com/Bropdrop/WolfTrap/blob/main/README.md
- WolfNet feature branch uses Linux libsodium ABI for Ed25519 with constrained installed library paths; reviewed blob `12e0221393b31e3a87f8e1fb31757d4313f296a8`: https://github.com/Bropdrop/WolfTrap/blob/feat/wolfnet-threat-registry-v1/src/wolftrap/wolfnet_crypto.py
- Governed release PR #26 remains open; its published body identifies candidate `7d9d753247f878d731f7c92b0f95d9f619a725b2` and production BLOCKED. This is a reported candidate, not a verified current head: https://github.com/Bropdrop/WolfTrap/pull/26
- Release verifier policy source reviewed at feature branch, blob `22c2887fb6892df2932fcb47046accd6a34b3e77`: https://github.com/Bropdrop/WolfTrap/blob/feat/governed-production-release-v1/release/verifier/release_policy.py

## Standards references

NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
OpenSSL pkeyutl 3.5: https://docs.openssl.org/3.5/man1/openssl-pkeyutl/

See CODEX-HANDOFF.md for the next qualification stage. Do not deploy this prototype.
