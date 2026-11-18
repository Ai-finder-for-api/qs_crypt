/**
 * @file qs_crypt_unsupported.c
 * @brief Interface boundaries with NO native implementation in this build.
 *
 * Every function here returns QSC_ERROR_UNSUPPORTED. They exist so the public
 * API is stable and so a compatibility backend can be wired in behind them.
 * Nothing here silently produces output.
 */
#include "qs_crypt/qs_crypt.h"
#include <stddef.h>

qsc_error_t qsc_keypair_generate(qsc_algorithm_id_t alg, qsc_keypair_t** kp) {
    (void)alg; if (kp) *kp = NULL; return QSC_ERROR_UNSUPPORTED;
}
qsc_error_t qsc_pubkey_from_keypair(const qsc_keypair_t* kp, qsc_pubkey_t** pk) {
    (void)kp; if (pk) *pk = NULL; return QSC_ERROR_UNSUPPORTED;
}
qsc_error_t qsc_pke_encrypt(const qsc_pubkey_t* pk, qsc_slice_t pt, qsc_buffer_t* ct) {
    (void)pk; (void)pt; (void)ct; return QSC_ERROR_UNSUPPORTED;
}
qsc_error_t qsc_pke_decrypt(const qsc_keypair_t* kp, qsc_slice_t ct, qsc_buffer_t* pt) {
    (void)kp; (void)ct; (void)pt; return QSC_ERROR_UNSUPPORTED;
}
void qsc_keypair_destroy(qsc_keypair_t* kp) { (void)kp; }
void qsc_pubkey_destroy(qsc_pubkey_t* pk) { (void)pk; }
qsc_error_t qsc_sign(const qsc_keypair_t* kp, qsc_slice_t msg, qsc_buffer_t* sig) {
    (void)kp; (void)msg; (void)sig; return QSC_ERROR_UNSUPPORTED;
}
qsc_error_t qsc_verify(const qsc_pubkey_t* pk, qsc_slice_t msg, qsc_slice_t sig) {
    (void)pk; (void)msg; (void)sig; return QSC_ERROR_UNSUPPORTED;
}
qsc_error_t qsc_kem_encapsulate(const qsc_pubkey_t* pk, qsc_buffer_t* ct, qsc_buffer_t* ss) {
    (void)pk; (void)ct; (void)ss; return QSC_ERROR_UNSUPPORTED;
}
qsc_error_t qsc_kem_decapsulate(const qsc_keypair_t* kp, qsc_slice_t ct, qsc_buffer_t* ss) {
    (void)kp; (void)ct; (void)ss; return QSC_ERROR_UNSUPPORTED;
}
qs_bool_t qsc_pq_backend_available(qsc_algorithm_id_t alg) {
    (void)alg; return QS_FALSE;
}
