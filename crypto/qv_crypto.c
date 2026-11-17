/* qv_crypto.c - QuantumVault crypto engine implementation
 *
 * implements the frozen contract in qv_crypto.h. the three demos proved
 * the algorithms; this file is the product the rust side links against.
 *
 * design:
 *   - algorithm handles (OQS_KEM / OQS_SIG) are fetched once in qv_init
 *     and cached - OQS_*_new is a lookup, per-process caching is the
 *     right pattern
 *   - engine never mallocs: caller allocates, caller frees, caller wipes
 *     secret buffers (rust side will use zeroize)
 *   - qv_encrypt generates the IV internally (RAND_bytes) so no caller
 *     can ever reuse a GCM IV with a key
 *   - every definition below mirrors the header's signatures verbatim,
 *     array notation included: declaration/definition drift is exactly
 *     what -Warray-parameter catches. bar: zero warnings under
 *     -Wall -Wextra, fixed at birth.
 *
 * EVP pattern per openssl's own demos/cipher/aesgcm.c; OSSL_PARAM arrays
 * are declared initialized (OSSL_PARAM_END is a brace initializer and
 * cannot be assigned mid-function).
 */
#include "qv_crypto.h"

#include <stdio.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* cached algorithm handles - set in qv_init, freed in qv_deinit */
static OQS_KEM *g_kem = NULL;
static OQS_SIG *g_sig = NULL;

int qv_init(void)
{
    if (g_kem && g_sig) return QV_OK;          /* idempotent */
    OQS_init();
    g_kem = OQS_KEM_new("ML-KEM-768");
    g_sig = OQS_SIG_new("ML-DSA-65");
    if (!g_kem || !g_sig) {
        qv_deinit();
        return QV_ERR_CRYPTO;
    }
    return QV_OK;
}

void qv_deinit(void)
{
    if (g_kem) { OQS_KEM_free(g_kem); g_kem = NULL; }
    if (g_sig) { OQS_SIG_free(g_sig); g_sig = NULL; }
}

/* ---- key delivery: ML-KEM-768 ---- */

int qv_kem_keypair(uint8_t pk[QV_KEM_PK_BYTES],
                   uint8_t sk[QV_KEM_SK_BYTES])
{
    if (!g_kem || !pk || !sk) return QV_ERR_PARAM;
    return OQS_KEM_keypair(g_kem, pk, sk) == OQS_SUCCESS ? QV_OK : QV_ERR_CRYPTO;
}

int qv_file_key_wrap(const uint8_t pk[QV_KEM_PK_BYTES],
                     uint8_t kem_ct[QV_KEM_CT_BYTES],
                     uint8_t file_key[QV_FILE_KEY_BYTES])
{
    if (!g_kem || !pk || !kem_ct || !file_key) return QV_ERR_PARAM;
    return OQS_KEM_encaps(g_kem, kem_ct, file_key, pk) == OQS_SUCCESS
           ? QV_OK : QV_ERR_CRYPTO;
}

int qv_file_key_unwrap(const uint8_t kem_ct[QV_KEM_CT_BYTES],
                       const uint8_t sk[QV_KEM_SK_BYTES],
                       uint8_t file_key[QV_FILE_KEY_BYTES])
{
    if (!g_kem || !kem_ct || !sk || !file_key) return QV_ERR_PARAM;
    return OQS_KEM_decaps(g_kem, file_key, kem_ct, sk) == OQS_SUCCESS
           ? QV_OK : QV_ERR_CRYPTO;
}

/* ---- bulk encryption: AES-256-GCM ---- */

int qv_encrypt(const uint8_t file_key[QV_FILE_KEY_BYTES],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *pt, size_t pt_len, uint8_t *ct,
               uint8_t iv[QV_IV_BYTES],
               uint8_t tag[QV_TAG_BYTES])
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    int outl = 0, finlen = 0;
    uint8_t fin[EVP_MAX_BLOCK_LENGTH];
    int ok = 0;

    if (!file_key || !iv || !tag || (!pt && pt_len) || (!ct && pt_len)
        || (!aad && aad_len))
        return QV_ERR_PARAM;

    /* the engine owns IV generation - callers cannot misuse GCM */
    if (RAND_bytes(iv, QV_IV_BYTES) != 1) return QV_ERR_CRYPTO;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx) goto err;

    if (!EVP_EncryptInit_ex2(ctx, cipher, file_key, iv, NULL)) goto err;

    if (aad_len > 0 &&
        !EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len)) goto err;

    if (pt_len > 0 &&
        !EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)pt_len)) goto err;

    if (!EVP_EncryptFinal_ex(ctx, fin, &finlen)) goto err;  /* GCM: no out */

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag, QV_TAG_BYTES);
    if (!EVP_CIPHER_CTX_get_params(ctx, params)) goto err;

    ok = 1;
err:
    if (!ok) ERR_print_errors_fp(stderr);
    if (cipher) EVP_CIPHER_free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok ? QV_OK : QV_ERR_CRYPTO;
}

int qv_decrypt(const uint8_t file_key[QV_FILE_KEY_BYTES],
               const uint8_t iv[QV_IV_BYTES],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *ct, size_t ct_len,
               const uint8_t tag[QV_TAG_BYTES],
               uint8_t *pt)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    int outl = 0, finlen = 0, rv;
    uint8_t fin[EVP_MAX_BLOCK_LENGTH];
    int ok = 0;

    if (!file_key || !iv || !tag || (!ct && ct_len) || (!pt && ct_len)
        || (!aad && aad_len))
        return QV_ERR_PARAM;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx) goto err;

    if (!EVP_DecryptInit_ex2(ctx, cipher, file_key, iv, NULL)) goto err;

    if (aad_len > 0 &&
        !EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len)) goto err;

    if (ct_len > 0 &&
        !EVP_DecryptUpdate(ctx, pt, &outl, ct, (int)ct_len)) goto err;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, (void *)tag, QV_TAG_BYTES);
    if (!EVP_CIPHER_CTX_set_params(ctx, params)) goto err;

    rv = EVP_DecryptFinal_ex(ctx, fin, &finlen);
    if (rv <= 0) { ok = 0; goto err; }   /* authentication failed */

    ok = 1;
err:
    if (!ok) ERR_print_errors_fp(stderr);
    if (cipher) EVP_CIPHER_free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok ? QV_OK : QV_ERR_CRYPTO;
}

/* ---- file proofs: ML-DSA-65 ---- */

int qv_sig_keypair(uint8_t pk[QV_SIG_PK_BYTES],
                   uint8_t sk[QV_SIG_SK_BYTES])
{
    if (!g_sig || !pk || !sk) return QV_ERR_PARAM;
    return OQS_SIG_keypair(g_sig, pk, sk) == OQS_SUCCESS ? QV_OK : QV_ERR_CRYPTO;
}

int qv_sign(const uint8_t *msg, size_t msg_len,
            const uint8_t sk[QV_SIG_SK_BYTES],
            uint8_t *sig, size_t *sig_len)
{
    if (!g_sig || (!msg && msg_len) || !sk || !sig || !sig_len)
        return QV_ERR_PARAM;
    return OQS_SIG_sign(g_sig, sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS
           ? QV_OK : QV_ERR_CRYPTO;
}

int qv_verify(const uint8_t *msg, size_t msg_len,
              const uint8_t *sig, size_t sig_len,
              const uint8_t pk[QV_SIG_PK_BYTES])
{
    if (!g_sig || (!msg && msg_len) || !sig || !sig_len || !pk)
        return QV_ERR_PARAM;
    return OQS_SIG_verify(g_sig, msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS
           ? QV_OK : QV_ERR_CRYPTO;
}
