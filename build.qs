module qs_crypt {
    name = "qs_crypt";
    version = "0.2.0";
    language = "c";
    standard = "c11";

    sources = [
        "src/core/qs_crypt_core.c",
        "src/core/qs_crypt_alloc.c",
        "src/core/qs_crypt_registry.c",
        "src/random/qs_crypt_random.c",
        "src/hash/qs_crypt_sha256.c",
        "src/hash/qs_crypt_sha512.c",
        "src/hash/qs_crypt_keccak.c",
        "src/hash/qs_crypt_hstate.c",
        "src/hash/qs_crypt_hash_dispatch.c",
        "src/mac/qs_crypt_hmac.c",
        "src/kdf/qs_crypt_hkdf.c",
        "src/symmetric/qs_crypt_chacha20.c",
        "src/aead/qs_crypt_poly1305.c",
        "src/aead/qs_crypt_chacha20poly1305.c",
        "src/aead/qs_crypt_aes_gcm.c",
        "src/aead/qs_crypt_aead_dispatch.c",
        "src/asymmetric/qs_crypt_fe25519.c",
        "src/asymmetric/qs_crypt_x25519.c",
        "src/asymmetric/qs_crypt_ed25519.c",
        "src/asymmetric/qs_crypt_unsupported.c",
        "src/key_management/qs_crypt_keys.c",
        "src/serialization/qs_crypt_wire.c",
        "src/containers/qs_crypt_seal.c",
        "src/experimental/qs_crypt_xof_experimental.c",
        "src/fhe/qs_crypt_bfv.c",
        "src/fhe/qs_crypt_ntt.c",
        "src/rsa/qs_crypt_bn.c",
        "src/rsa/qs_crypt_rsa.c",
        "src/ecdsa/qs_crypt_ecdsa.c",
        "src/mlkem/qs_crypt_mlkem.c",
        "src/mldsa/qs_crypt_mldsa.c",
    ];

    headers = [
        "include/qs_crypt/qs_crypt.h",
        "include/qs_crypt/qs_crypt_experimental.h",
        "include/qs_crypt/qs_crypt_fhe.h",
        "include/qs_crypt/qs_crypt_rsa.h",
        "include/qs_crypt/qs_crypt_ecdsa.h",
        "include/qs_crypt/qs_crypt_mlkem.h",
        "include/qs_crypt/qs_crypt_mldsa.h",
    ];

    modules = [];

    dependencies = [];   // Standalone: includes its own memory pool; no qs_memory or qs_math.

    windows_link = [ "bcrypt" ];

    tests = [
        "tests/test_main.c",
        "tests/unit/test_api.c",
        "tests/negative/test_negative.c",
        "tests/serialization/test_container.c",
        "tests/property/test_property.c",
        "tests/known_answer/test_kat.c",
        "tests/known_answer/test_kat2.c",
        "tests/known_answer/test_ed25519.c",
        "tests/fhe/test_fhe.c",
        "tests/rsa/test_rsa.c",
        "tests/ecdsa/test_ecdsa.c",
        "tests/mlkem/test_mlkem.c",
        "tests/mldsa/test_mldsa.c",
    ];
}
