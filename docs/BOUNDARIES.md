# QScrypt integration boundaries

## FHE (QuantumCrypt)
QScrypt does not implement BFV, CKKS, BGV, RNS, or NTT. Polynomial arithmetic belongs to the
math/FHE subsystem and must not be added to qs_crypt. QScrypt supplies key objects
(`qsc_key_t`), containers, and wire envelopes that the FHE layer may reuse.

## SEAL compatibility backend
Intended shape:

    QScrypt public API
        -> backend interface (asymmetric/, kem/, signatures/ stubs)
            -> SEAL adapter (separate, optional, not in this module)

The adapter must not fork or copy SEAL, and SEAL must not become the native implementation.
Until an adapter exists, every backend-backed function returns QSC_ERROR_UNSUPPORTED.

## Standardized post-quantum primitives
ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) are compatibility backends, not
QScrypt-native code. `qsc_pq_backend_available` reports whether one is registered.

## Windows
Entropy uses BCryptGenRandom (link `bcrypt`). Locking uses SRWLOCK. Both are written but
have NOT been compiled or tested on Windows in this environment.
