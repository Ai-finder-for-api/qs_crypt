/**
 * @file qs_crypt_containers.h
 * @brief Sealed ciphertext container: algorithm id + nonce + tag + body.
 *
 * Binds the algorithm to the data so a ciphertext cannot be decrypted under a
 * different algorithm than the one that produced it.
 */
#ifndef QS_CRYPT_CONTAINERS_H
#define QS_CRYPT_CONTAINERS_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Seal: generates a random nonce, encrypts, and emits a serialized container. */
qsc_error_t qsc_seal(const qsc_key_t* key, qsc_slice_t aad,
                     qsc_slice_t plaintext, qsc_buffer_t* container_out);

/* Open: parses the container, checks alg matches key, verifies tag, decrypts. */
qsc_error_t qsc_open(const qsc_key_t* key, qsc_slice_t aad,
                     qsc_slice_t container, qsc_buffer_t* plaintext_out);

void qsc_buffer_free(qsc_buffer_t* buf); /* zeroizes then releases */

#ifdef __cplusplus
}
#endif
#endif
