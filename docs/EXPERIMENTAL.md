# EXPERIMENTAL components

## qs_crypt_experimental.h — domain-separated XOF v0
- Opt-in: not included by `qs_crypt.h`. Must be included explicitly.
- Construction: SHAKE256("QSCRYPT-XOF-EXP-V0" || len||domain || len||input), output length chosen by the caller.
- Output size is NOT a security level. SHAKE256 has a 512-bit capacity, so collision resistance is about 2^128 and preimage resistance about 2^256 regardless of output length. A 4096-bit (512-byte) output does not make the construction harder to break than SHAKE256.
- No independent cryptanalysis. Not a claim of security.
- Use SHA3-256 or SHAKE256 directly for production hashing.

## Evidence required before leaving EXPERIMENTAL
1. Published specification (this file is not one).
2. Reference test vectors from an independent implementation.
3. Independent cryptanalysis by parties outside the project.
4. Side-channel review of the implementation.
