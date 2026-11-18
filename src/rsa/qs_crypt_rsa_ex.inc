/* qs_crypt_rsa_ex.inc - included at the end of qs_crypt_rsa.c (needs its static helpers).
 *
 * Generic-hash RSA added for JOSE: PKCS#1 v1.5 (RS256/384/512), PSS and OAEP over
 * SHA-256/384/512, and CRT private key import. The original SHA-256-only entry points
 * in qs_crypt_rsa.c are unchanged.
 */

#define HMAXL 64

static size_t hlen_of(qsc_algorithm_id_t a) {
    switch (a) {
        case QSC_ALG_SHA2_256: return 32;
        case QSC_ALG_SHA2_384: return 48;
        case QSC_ALG_SHA2_512: return 64;
        default: return 0;
    }
}

static qsc_error_t hg(qsc_algorithm_id_t alg, uint8_t* out,
                      const uint8_t* a, size_t al, const uint8_t* b, size_t bl,
                      const uint8_t* c, size_t cl) {
    qsc_hash_ctx_t* h = NULL;
    qsc_digest_t d;
    qsc_error_t e = qsc_hash_begin(alg, &h);
    if (e != QSC_OK) return e;
    if (al) { e = qsc_hash_update(h, (qsc_slice_t){ a, al }); if (e != QSC_OK) { qsc_hash_destroy(h); return e; } }
    if (bl) { e = qsc_hash_update(h, (qsc_slice_t){ b, bl }); if (e != QSC_OK) { qsc_hash_destroy(h); return e; } }
    if (cl) { e = qsc_hash_update(h, (qsc_slice_t){ c, cl }); if (e != QSC_OK) { qsc_hash_destroy(h); return e; } }
    e = qsc_hash_finish(h, &d);
    if (e != QSC_OK) return e;
    memcpy(out, d.data, (size_t)d.length);
    return QSC_OK;
}

static qsc_error_t mgf1g(qsc_algorithm_id_t alg, const uint8_t* seed, size_t slen,
                         uint8_t* mask, size_t mlen) {
    const size_t hl = hlen_of(alg);
    uint8_t dg[HMAXL];
    size_t off = 0;
    for (uint32_t ctr = 0; off < mlen; ctr++) {
        uint8_t c4[4] = { (uint8_t)(ctr >> 24), (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 8), (uint8_t)ctr };
        qsc_error_t e = hg(alg, dg, seed, slen, c4, 4, NULL, 0);
        if (e != QSC_OK) return e;
        size_t take = (mlen - off < hl) ? (mlen - off) : hl;
        memcpy(mask + off, dg, take);
        off += take;
    }
    return QSC_OK;
}

/* ---- PKCS#1 v1.5 signatures (RFC 8017 section 8.2) ---------------------------------- */

static const uint8_t DI256[19] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
static const uint8_t DI384[19] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
static const uint8_t DI512[19] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};

/* Builds EM = 00 01 FF..FF 00 || DigestInfo || H for the message. */
static qsc_error_t pkcs1_encode(qsc_algorithm_id_t alg, qsc_slice_t msg, uint8_t* em, size_t k) {
    const size_t hl = hlen_of(alg);
    const uint8_t* di;
    uint8_t h[HMAXL];
    qsc_error_t e;
    size_t tlen;
    if (!hl) return QSC_ERROR_UNSUPPORTED;
    di = (alg == QSC_ALG_SHA2_256) ? DI256 : (alg == QSC_ALG_SHA2_384) ? DI384 : DI512;
    tlen = 19 + hl;
    if (k < tlen + 11) return QSC_ERROR_INVALID_PARAMETERS;
    if ((e = hg(alg, h, msg.data, (size_t)msg.length, NULL, 0, NULL, 0)) != QSC_OK) return e;
    em[0] = 0x00; em[1] = 0x01;
    memset(em + 2, 0xFF, k - tlen - 3);
    em[k - tlen - 1] = 0x00;
    memcpy(em + k - tlen, di, 19);
    memcpy(em + k - hl, h, hl);
    return QSC_OK;
}

qsc_error_t qsc_rsa_pkcs1_sign(const qsc_rsa_private_t* priv, qsc_algorithm_id_t hash,
                               qsc_slice_t msg, qsc_buffer_t* sig) {
    uint8_t em[QSC_BN_MAX * 4];
    qsc_bn m, s;
    qsc_error_t err;
    size_t k;
    if (!priv_ok(priv) || !sig || !sig->data || (msg.length && !msg.data)) return QSC_ERROR_INVALID_ARGUMENT;
    k = (size_t)priv->kn * 4;
    if (sig->length < k) { sig->length = k; return QSC_ERROR_BUFFER_TOO_SMALL; }
    if ((err = pkcs1_encode(hash, msg, em, k)) != QSC_OK) return err;
    qsc_bn_from_be(&m, priv->kn, em, k);
    if (!rsa_priv_op_blind(priv, &s, &m)) { qsc_secure_zero(em, sizeof em); return QSC_ERROR_INVALID_SIGNATURE; }
    qsc_bn_to_be(&s, priv->kn, sig->data, k);
    sig->length = k;
    qsc_secure_zero(em, sizeof em);
    return QSC_OK;
}

/* Verification re-encodes the expected block and compares it in full. There is no parser for
 * the padding, so a malformed-padding forgery has nothing to exploit. */
qsc_error_t qsc_rsa_pkcs1_verify(const qsc_rsa_public_t* pub, qsc_algorithm_id_t hash,
                                 qsc_slice_t msg, qsc_slice_t sig) {
    uint8_t want[QSC_BN_MAX * 4], got[QSC_BN_MAX * 4];
    qsc_bn s, m;
    qsc_error_t err;
    size_t k;
    uint8_t diff = 0;
    if (!pub_ok(pub) || (!msg.data && msg.length) || !sig.data) return QSC_ERROR_INVALID_ARGUMENT;
    k = (size_t)pub->kn * 4;
    if (sig.length != k) return QSC_ERROR_INVALID_SIGNATURE;
    if (qsc_bn_from_be(&s, pub->kn, sig.data, k) != 0) return QSC_ERROR_INVALID_SIGNATURE;
    if (qsc_bn_cmp(&s, &pub->mont.n, pub->kn) >= 0) return QSC_ERROR_INVALID_SIGNATURE;
    if ((err = pkcs1_encode(hash, msg, want, k)) != QSC_OK) return err;
    rsa_pub_op(pub, &m, &s);
    qsc_bn_to_be(&m, pub->kn, got, k);
    for (size_t i = 0; i < k; i++) diff |= (uint8_t)(want[i] ^ got[i]);
    return diff == 0 ? QSC_OK : QSC_ERROR_INVALID_SIGNATURE;
}

/* ---- PSS with a selectable hash (salt length = hash length, MGF1 with the same hash) ---- */

qsc_error_t qsc_rsa_pss_sign_ex(const qsc_rsa_private_t* priv, qsc_algorithm_id_t hash,
                                qsc_slice_t msg, qsc_buffer_t* sig) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], mh[HMAXL], salt[HMAXL], h[HMAXL];
    uint8_t pre[8] = { 0 };
    qsc_bn m, s;
    qsc_error_t err;
    const size_t hl = hlen_of(hash);
    size_t k, dblen, ps;
    if (!hl) return QSC_ERROR_UNSUPPORTED;
    if (!priv_ok(priv) || !sig || !sig->data || (msg.length && !msg.data)) return QSC_ERROR_INVALID_ARGUMENT;
    k = (size_t)priv->kn * 4;
    if (sig->length < k) { sig->length = k; return QSC_ERROR_BUFFER_TOO_SMALL; }
    if ((err = hg(hash, mh, msg.data, (size_t)msg.length, NULL, 0, NULL, 0)) != QSC_OK) return err;
    if ((err = qsc_random_bytes(salt, hl)) != QSC_OK) return err;
    if ((err = hg(hash, h, pre, 8, mh, hl, salt, hl)) != QSC_OK) return err;
    dblen = k - hl - 1;
    ps = dblen - hl - 1;
    memset(em, 0, ps);
    em[ps] = 0x01;
    memcpy(em + ps + 1, salt, hl);
    if ((err = mgf1g(hash, h, hl, mask, dblen)) != QSC_OK) return err;
    for (size_t i = 0; i < dblen; i++) em[i] ^= mask[i];
    em[0] &= 0x7F;
    memcpy(em + dblen, h, hl);
    em[k - 1] = 0xBC;
    qsc_bn_from_be(&m, priv->kn, em, k);
    if (!rsa_priv_op_blind(priv, &s, &m)) { qsc_secure_zero(em, sizeof em); return QSC_ERROR_INVALID_SIGNATURE; }
    qsc_bn_to_be(&s, priv->kn, sig->data, k);
    sig->length = k;
    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return QSC_OK;
}

qsc_error_t qsc_rsa_pss_verify_ex(const qsc_rsa_public_t* pub, qsc_algorithm_id_t hash,
                                  qsc_slice_t msg, qsc_slice_t sig) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], mh[HMAXL], h2[HMAXL];
    uint8_t pre[8] = { 0 };
    qsc_bn s, m;
    qsc_error_t err;
    const size_t hl = hlen_of(hash);
    size_t k, dblen, ps;
    uint32_t ok;
    uint8_t zero = 0;
    const uint8_t *h, *salt;
    if (!hl) return QSC_ERROR_UNSUPPORTED;
    if (!pub_ok(pub) || (!msg.data && msg.length) || !sig.data) return QSC_ERROR_INVALID_ARGUMENT;
    k = (size_t)pub->kn * 4;
    if (sig.length != k) return QSC_ERROR_INVALID_SIGNATURE;
    if (qsc_bn_from_be(&s, pub->kn, sig.data, k) != 0) return QSC_ERROR_INVALID_SIGNATURE;
    if (qsc_bn_cmp(&s, &pub->mont.n, pub->kn) >= 0) return QSC_ERROR_INVALID_SIGNATURE;
    rsa_pub_op(pub, &m, &s);
    qsc_bn_to_be(&m, pub->kn, em, k);
    dblen = k - hl - 1;
    h = em + dblen;
    ok = (uint32_t)(em[k - 1] == 0xBC) & (uint32_t)((em[0] & 0x80) == 0);
    if ((err = mgf1g(hash, h, hl, mask, dblen)) != QSC_OK) return err;
    for (size_t i = 0; i < dblen; i++) em[i] ^= mask[i];
    em[0] &= 0x7F;
    ps = dblen - hl - 1;
    for (size_t i = 0; i < ps; i++) zero |= em[i];
    ok &= (uint32_t)(zero == 0);
    ok &= (uint32_t)(em[ps] == 0x01);
    salt = em + ps + 1;
    if ((err = hg(hash, mh, msg.data, (size_t)msg.length, NULL, 0, NULL, 0)) != QSC_OK) return err;
    if ((err = hg(hash, h2, pre, 8, mh, hl, salt, hl)) != QSC_OK) return err;
    ok &= qsc_constant_time_equal(h2, h, hl) ? 1u : 0u;
    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return ok ? QSC_OK : QSC_ERROR_INVALID_SIGNATURE;
}

/* ---- OAEP with a selectable hash, empty label ------------------------------------------ */

qsc_error_t qsc_rsa_oaep_encrypt_ex(const qsc_rsa_public_t* pub, qsc_algorithm_id_t hash,
                                    qsc_slice_t msg, qsc_buffer_t* ct) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], lh[HMAXL];
    qsc_bn m, c;
    qsc_error_t err;
    const size_t hl = hlen_of(hash);
    size_t k, dblen;
    uint8_t *seed, *db;
    if (!hl) return QSC_ERROR_UNSUPPORTED;
    if (!pub_ok(pub) || !ct || !ct->data || (msg.length && !msg.data)) return QSC_ERROR_INVALID_ARGUMENT;
    k = (size_t)pub->kn * 4;
    if (msg.length > k - 2 * hl - 2) return QSC_ERROR_INVALID_PARAMETERS;
    if (ct->length < k) { ct->length = k; return QSC_ERROR_BUFFER_TOO_SMALL; }
    seed = em + 1;
    db = em + 1 + hl;
    dblen = k - hl - 1;
    if ((err = hg(hash, lh, NULL, 0, NULL, 0, NULL, 0)) != QSC_OK) return err;
    em[0] = 0;
    if ((err = qsc_random_bytes(seed, hl)) != QSC_OK) return err;
    memcpy(db, lh, hl);
    memset(db + hl, 0, dblen - hl - 1 - (size_t)msg.length);
    db[dblen - (size_t)msg.length - 1] = 0x01;
    if (msg.length) memcpy(db + dblen - (size_t)msg.length, msg.data, (size_t)msg.length);
    if ((err = mgf1g(hash, seed, hl, mask, dblen)) != QSC_OK) return err;
    for (size_t i = 0; i < dblen; i++) db[i] ^= mask[i];
    if ((err = mgf1g(hash, db, dblen, mask, hl)) != QSC_OK) return err;
    for (size_t i = 0; i < hl; i++) seed[i] ^= mask[i];
    qsc_bn_from_be(&m, pub->kn, em, k);
    rsa_pub_op(pub, &c, &m);
    qsc_bn_to_be(&c, pub->kn, ct->data, k);
    ct->length = k;
    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return QSC_OK;
}

qsc_error_t qsc_rsa_oaep_decrypt_ex(const qsc_rsa_private_t* priv, qsc_algorithm_id_t hash,
                                    qsc_slice_t ct, qsc_buffer_t* msg) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], lh[HMAXL];
    qsc_bn c, m;
    qsc_error_t err;
    const size_t hl = hlen_of(hash);
    size_t k, dblen, idx = 0;
    uint8_t *seed, *db;
    uint32_t bad, lhdiff = 0, found = 0;
    if (!hl) return QSC_ERROR_UNSUPPORTED;
    if (!priv_ok(priv) || !msg || !msg->data || !ct.data) return QSC_ERROR_INVALID_ARGUMENT;
    k = (size_t)priv->kn * 4;
    if (ct.length != k) return QSC_ERROR_DECRYPTION_FAILED;
    if (qsc_bn_from_be(&c, priv->kn, ct.data, k) != 0) return QSC_ERROR_DECRYPTION_FAILED;
    if (qsc_bn_cmp(&c, &priv->mont.n, priv->kn) >= 0) return QSC_ERROR_DECRYPTION_FAILED;
    if (!rsa_priv_op_blind(priv, &m, &c)) { err = QSC_ERROR_DECRYPTION_FAILED; goto done; }
    qsc_bn_to_be(&m, priv->kn, em, k);
    seed = em + 1;
    db = em + 1 + hl;
    dblen = k - hl - 1;
    bad = (uint32_t)(em[0] != 0);
    if ((err = mgf1g(hash, db, dblen, mask, hl)) != QSC_OK) goto done;
    for (size_t i = 0; i < hl; i++) seed[i] ^= mask[i];
    if ((err = mgf1g(hash, seed, hl, mask, dblen)) != QSC_OK) goto done;
    for (size_t i = 0; i < dblen; i++) db[i] ^= mask[i];
    if ((err = hg(hash, lh, NULL, 0, NULL, 0, NULL, 0)) != QSC_OK) goto done;
    for (size_t j = 0; j < hl; j++) lhdiff |= (uint32_t)(db[j] ^ lh[j]);
    bad |= (lhdiff != 0);
    for (size_t j = hl; j < dblen; j++) {
        uint32_t nz = (db[j] != 0);
        uint32_t first = nz & ~found;
        size_t fmask = (size_t)0 - (size_t)first;
        bad |= first & (uint32_t)(db[j] != 1);
        idx = (idx & ~fmask) | (j & fmask);
        found |= nz;
    }
    bad |= ~found & 1u;
    if (bad) { err = QSC_ERROR_DECRYPTION_FAILED; goto done; }
    {
        size_t mlen = dblen - idx - 1;
        if (msg->length < mlen) { msg->length = mlen; err = QSC_ERROR_BUFFER_TOO_SMALL; goto done; }
        memcpy(msg->data, db + idx + 1, mlen);
        msg->length = mlen;
        err = QSC_OK;
    }
done:
    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return err;
}

/* ---- Private key import with CRT parameters (CRT speed + blinding) ----------------------- */

qsc_error_t qsc_rsa_private_create_crt(qsc_slice_t n, qsc_slice_t e, qsc_slice_t d,
                                       qsc_slice_t p, qsc_slice_t q, qsc_rsa_private_t** out) {
    const qs_u8 *np = n.data, *ep = e.data, *dp_ = d.data, *pp = p.data, *qp = q.data;
    qs_u64 nl = n.length, el = e.length, dl = d.length, pl = p.length, ql = q.length;
    qsc_bn nb, db, pb, qb, nchk, pm1, qm1, phi, one;
    uint32_t ev = 0, bits;
    int kn, kp;
    qsc_rsa_private_t* priv;
    if (!out || !np || !ep || !dp_ || !pp || !qp) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    strip_zeros(&np, &nl); strip_zeros(&ep, &el); strip_zeros(&dp_, &dl);
    strip_zeros(&pp, &pl); strip_zeros(&qp, &ql);
    if (nl != 256 && nl != 384 && nl != 512) return QSC_ERROR_KEY_SIZE_MISMATCH;
    if (el == 0 || el > 4) return QSC_ERROR_INVALID_KEY;
    for (qs_u64 i = 0; i < el; i++) ev = (ev << 8) | ep[i];
    if (ev < 3 || !(ev & 1u)) return QSC_ERROR_INVALID_KEY;
    bits = (uint32_t)(nl * 8);
    kn = kn_for_bits(bits);
    kp = kn / 2;
    if (!kn || dl == 0 || dl > (qs_u64)kn * 4) return QSC_ERROR_INVALID_KEY;
    if (pl == 0 || pl > (qs_u64)kp * 4 || ql == 0 || ql > (qs_u64)kp * 4) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_from_be(&nb, kn, np, (size_t)nl) != 0) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_from_be(&db, kn, dp_, (size_t)dl) != 0) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_from_be(&pb, kp, pp, (size_t)pl) != 0) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_from_be(&qb, kp, qp, (size_t)ql) != 0) return QSC_ERROR_INVALID_KEY;
    if (!(nb.w[0] & 1u) || !(pb.w[0] & 1u) || !(qb.w[0] & 1u)) return QSC_ERROR_INVALID_KEY;
    qsc_bn_mul(&nchk, &pb, &qb, kp);                      /* p * q must equal n exactly */
    if (qsc_bn_cmp(&nchk, &nb, kn) != 0) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_bit_len(&db, kn) == 0 || qsc_bn_cmp(&db, &nb, kn) >= 0) return QSC_ERROR_INVALID_KEY;

    priv = (qsc_rsa_private_t*)qsc_alloc(sizeof *priv);
    if (!priv) return QSC_ERROR_OOM;
    memset(priv, 0, sizeof *priv);
    priv->magic = RSA_PRIV_MAGIC;
    priv->kn = kn;
    priv->bits = bits;
    qsc_mont_init(&priv->mont, &nb, kn);
    qsc_bn_zero(&priv->d);
    qsc_bn_copy(&priv->d, &db, kn);
    qsc_bn_set_u32(&one, 1);
    qsc_bn_sub(&pm1, &pb, &one, kp);
    qsc_bn_sub(&qm1, &qb, &one, kp);
    qsc_bn_mul(&phi, &pm1, &qm1, kp);
    qsc_bn_sub(&priv->phim1, &phi, &one, kn);
    priv->has_crt = 1;
    priv->kp = kp;
    priv->e = ev;
    qsc_bn_zero(&priv->p); qsc_bn_copy(&priv->p, &pb, kp);
    qsc_bn_zero(&priv->q); qsc_bn_copy(&priv->q, &qb, kp);
    qsc_bn_mod(&priv->dp, &db, kn, &pm1, kp);
    qsc_bn_mod(&priv->dq, &db, kn, &qm1, kp);
    qsc_mont_init(&priv->mp, &pb, kp);
    qsc_mont_init(&priv->mq, &qb, kp);
    {
        qsc_bn qpm, two, pm2, qinv;
        uint8_t pm2b[QSC_BN_MAX * 4];
        qsc_bn_mod(&qpm, &qb, kp, &pb, kp);
        qsc_bn_set_u32(&two, 2);
        qsc_bn_sub(&pm2, &pb, &two, kp);
        qsc_bn_to_be(&pm2, kp, pm2b, (size_t)kp * 4);
        qsc_mont_pow(&priv->mp, &qinv, &qpm, pm2b, (size_t)kp * 4);   /* q^(p-2) = q^-1 mod p */
        qsc_mont_to(&priv->mp, &priv->qinv_m, &qinv);
        qsc_secure_zero(pm2b, sizeof pm2b);
    }
    /* Consistency check: a fixed message must survive (m^e)^d. A wrong d, p or q fails here. */
    {
        qsc_bn t, x, y;
        uint8_t eb[4];
        size_t el2 = e_bytes(ev, eb);
        qsc_bn_zero(&t);
        qsc_bn_set_u32(&t, 0x5A17C0DEu);
        qsc_mont_pow(&priv->mont, &x, &t, eb, el2);
        if (!rsa_priv_op(priv, &y, &x) || qsc_bn_cmp(&y, &t, kn) != 0) {
            qsc_free_zero(priv, sizeof *priv);
            return QSC_ERROR_INVALID_KEY;
        }
    }
    *out = priv;
    return QSC_OK;
}
