# qs_crypt — HANDOFF (QScrypt 0.2.0)

## Status in one paragraph
Implemented and tested natively: SHA-2 (256/512), SHA-3 (256/512), SHAKE256, HMAC-SHA-2,
HKDF-SHA-2, ChaCha20, ChaCha20-Poly1305, AES-128/256 (FIPS 197) with AES-GCM, X25519
(RFC 7748), OS-entropy RNG, keys, a versioned wire format, sealed containers, a QScrypt-local
memory pool, and one opt-in EXPERIMENTAL XOF. NOT implemented: Ed25519, RSA (OAEP/PSS),
ECDSA/ECIES, ML-KEM, ML-DSA, SLH-DSA, the SEAL backend adapter, and FHE arithmetic (which
belongs to the math/FHE subsystem). Those functions return `QSC_ERROR_UNSUPPORTED`; nothing
silently produces output for them.

## What "hard to break" means here
Output length does not set security. The experimental XOF returns 512 bytes (4096 bits) but
is bounded by SHAKE256's 512-bit capacity (about 256-bit security). It has had no independent
analysis, so it is labelled EXPERIMENTAL / NOT FOR PRODUCTION. For production use, SHA3-256,
SHAKE256, and ChaCha20-Poly1305 or AES-256-GCM should be used. No QScrypt primitive is
claimed to be unbreakable.

## Layout
```
include/qs_crypt/   public API (qs_crypt.h umbrella; experimental header is opt-in)
include/core/       LOCAL stand-in for core/qs_types.h (replace in the monorepo)
src/core/           lifecycle, registry, secure zero, constant-time compare, memory pool
src/random/         OS entropy: getrandom / BCryptGenRandom / /dev/urandom
src/hash/           SHA-256, SHA-512, Keccak sponge, unified hash state, dispatch
src/mac/            HMAC-SHA-2 (generic over 256/512)
src/kdf/            HKDF-SHA-2 (generic), derive_key with mandatory domain label
src/symmetric/      ChaCha20 (RFC 8439), AES (in src/aead/qs_crypt_aes_gcm.c)
src/aead/           Poly1305, ChaCha20-Poly1305, AES-GCM, AEAD dispatch
src/asymmetric/     X25519 (RFC 7748); unsupported PKE stubs
src/key_management/ symmetric keys (exact size, weak-key rejection, zeroize)
src/serialization/  versioned wire envelope with strict parsing
src/containers/     sealed container; algorithm bound into the envelope
src/experimental/   XOF v0 (opt-in, see docs/EXPERIMENTAL.md)
tests/              KAT, KAT2, unit, negative, serialization, property, fuzz smoke
```

## Memory: QScrypt-local pool (no qs_memory)
`src/core/qs_crypt_alloc.c` is a size-class pool (16..4096 B) over 64 KiB slabs from the
system allocator, plus direct allocation above 4 KiB. Each block has a 16-byte header with a
magic value, so invalid frees are detected and counted. Freed memory is zeroized. Operations
are serialized by SRWLOCK (Windows) or a pthread mutex (POSIX). Slabs are retained until
process exit; the pool ceiling is 256 MiB of slabs. The test runner asserts zero live blocks
and zero invalid frees at exit.

## Verification
- `make test`: 15,247 checks, 0 failures, AddressSanitizer + UBSan (abort on first UB).
  Includes the leak check.
- Vectors: FIPS 180-4 (SHA-256, SHA-512), FIPS 202 (SHA3-256/512, SHAKE256), RFC 4231
  (HMAC-SHA-256 cases 1, 2, 6; HMAC-SHA-512 case 1), RFC 5869 (HKDF-SHA-256 case 1),
  FIPS 197 via GCM (AES-128 block through GCM test case 2), GCM test case 16 (AES-256,
  60-byte plaintext, 20-byte AAD), RFC 8439 (ChaCha20 2.3.2 and 2.4.2; ChaCha20-Poly1305
  2.8.2), RFC 7748 6.1 (X25519 Alice/Bob public keys and shared secret).
- Mutation check (earlier build): breaking Poly1305 reduction or constant-time compare makes
  the suite fail.
- Fuzz smoke: 200,000 random inputs to container unwrap/open under ASan, no authentication
  accepted. Not coverage-guided.
- `gcc -fanalyzer` per source file: 0 warnings (earlier build; re-run recommended).
- Public headers self-contained; umbrella header compiles as C++17.

Vectors were transcribed by hand and all matched. A transcription error that broke a match
would have shown as a failure, but the vectors should still be checked against the source
documents before release.

## Benchmarks (single run, this container, indicative only)
SHA-256 242 MiB/s; HMAC-SHA-256 241 MiB/s; ChaCha20 430 MiB/s; ChaCha20-Poly1305 encrypt
319 MiB/s, decrypt 288 MiB/s; seal 1 KiB 5.2 µs; HKDF-32 2.8 µs. Not comparable to other
libraries; not repeated; not tuned.

## Known limitations (read these)
1. AES is table-based: S-box lookups are data-dependent, so it is vulnerable to cache-timing
   attacks on shared hardware. ChaCha20-Poly1305 has no such issue. An AES-NI backend would
   fix this.
2. Constant-time behaviour is designed (no data-dependent branches in tag compare, Poly1305
   select, GHASH, and X25519 ladder swaps) but not verified by timing measurement or by
   inspecting compiler output.
3. Nonces are random 96-bit values with no reuse tracking. GCM and ChaCha20-Poly1305 with a
   random nonce are safe only well below ~2^32 messages per key.
4. X25519 requires `unsigned __int128` (GCC, Clang, Zig). MSVC cannot build it as written.
5. Windows code (BCryptGenRandom, SRWLOCK) is written but has NOT been compiled or run on
   Windows here. Link with `bcrypt`.
6. Not implemented: Ed25519, RSA, ECDSA, ECIES, ML-KEM, ML-DSA, SLH-DSA, SEAL adapter, FHE.
7. Poly1305 has no standalone RFC 8439 2.5.2 test; it is covered through the AEAD vector.
8. The allocator is single-lock; it will not scale across many threads. It also keeps slab
   memory until exit.
9. The `include/core/qs_types.h` stand-in must be replaced by the real header in the monorepo.
