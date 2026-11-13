/* qv_hybrid_demo.c - QuantumVault crypto engine, step 2: hybrid encryption
 *
 * full per-file pattern of the vault, end to end:
 *   1. ML-KEM-768 keypair (vault identity)
 *   2. encapsulate -> 32-byte shared secret = exactly an AES-256 key
 *   3. AES-256-GCM encrypt an actual message (fresh random 12-byte IV)
 *      with the Kyber ciphertext as AAD, so the tag also authenticates
 *      the key envelope, not just the content
 *   4. decrypt on the other side, verify plaintext
 *   5. tamper test A: flip one ciphertext byte  -> GCM must refuse
 *   6. tamper test B: flip one Kyber-ct byte    -> GCM must refuse (AAD)
 *
 * EVP pattern follows openssl's own demo: demos/cipher/aesgcm.c (3.x API:
 * EVP_CIPHER_fetch + Init_ex2 + OSSL_PARAM AEAD tag; DecryptFinal <= 0
 * means authentication failed).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void hexdump(const char *label, const uint8_t *buf, size_t n)
{
    printf("%-26s (%zu bytes): ", label, n);
    for (size_t i = 0; i < n && i < 16; i++)
        printf("%02x", buf[i]);
    if (n > 16) printf("...");
    printf("\n");
}

/* AES-256-GCM encrypt. key32=32B key, iv12=12B IV (GCM default size),
 * aad may be NULL. ct must have room for pt_len bytes, tag16 gets 16B.
 * returns 0 on success. */
static int aes_gcm_encrypt(const uint8_t *key32, const uint8_t *iv12,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t *tag16)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int outlen = 0, finlen = 0;
    uint8_t fin[EVP_MAX_BLOCK_LENGTH];
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL) goto err;

    if (!EVP_EncryptInit_ex2(ctx, cipher, key32, iv12, NULL)) goto err;

    if (aad_len > 0 &&
        !EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len))
        goto err;

    if (!EVP_EncryptUpdate(ctx, ct, &outlen, pt, (int)pt_len)) goto err;

    if (!EVP_EncryptFinal_ex(ctx, fin, &finlen)) goto err; /* GCM: no output */

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag16, 16);
    params[1] = OSSL_PARAM_END;
    if (!EVP_CIPHER_CTX_get_params(ctx, params)) goto err;

    ok = 1;
err:
    if (!ok) ERR_print_errors_fp(stderr);
    if (cipher) EVP_CIPHER_free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* AES-256-GCM decrypt. Returns 0 ONLY if the tag verifies; a tampered
 * ciphertext, tag, or AAD makes EVP_DecryptFinal_ex return <= 0. */
static int aes_gcm_decrypt(const uint8_t *key32, const uint8_t *iv12,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t *tag16, uint8_t *pt)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int outlen = 0, finlen = 0, rv;
    uint8_t fin[EVP_MAX_BLOCK_LENGTH];
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL) goto err;

    if (!EVP_DecryptInit_ex2(ctx, cipher, key32, iv12, NULL)) goto err;

    if (aad_len > 0 &&
        !EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len))
        goto err;

    if (!EVP_DecryptUpdate(ctx, pt, &outlen, ct, (int)ct_len)) goto err;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, (void *)tag16, 16);
    params[1] = OSSL_PARAM_END;
    if (!EVP_CIPHER_CTX_set_params(ctx, params)) goto err;

    rv = EVP_DecryptFinal_ex(ctx, fin, &finlen);
    if (rv <= 0) { ok = 0; goto err; }   /* authentication failed */

    ok = 1;
err:
    if (!ok) ERR_print_errors_fp(stderr);
    if (cipher) EVP_CIPHER_free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int main(void)
{
    const char *msg = "QuantumVault hybrid demo: kyber delivers the key, "
                      "AES-256-GCM protects the bytes.";
    size_t msg_len = strlen(msg);

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (kem == NULL) { fprintf(stderr, "ML-KEM-768 missing\n"); return 1; }

    uint8_t *pk     = malloc(kem->length_public_key);
    uint8_t *sk     = malloc(kem->length_secret_key);
    uint8_t *kem_ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);
    uint8_t *aes_ct = malloc(msg_len);
    uint8_t *pt     = malloc(msg_len + 1);
    if (!pk || !sk || !kem_ct || !ss_enc || !ss_dec || !aes_ct || !pt)
        { fprintf(stderr, "malloc failed\n"); return 1; }

    printf("=== stage 1: kyber delivers the key ===\n");
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) return 1;
    if (OQS_KEM_encaps(kem, kem_ct, ss_enc, pk) != OQS_SUCCESS) return 1;
    if (OQS_KEM_decaps(kem, ss_dec, kem_ct, sk) != OQS_SUCCESS) return 1;
    if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) != 0)
        { fprintf(stderr, "KEM secrets differ\n"); return 1; }
    printf("shared secret agreed   : %zu bytes (exactly an AES-256 key)\n",
           kem->length_shared_secret);
    hexdump("kem ciphertext (AAD)", kem_ct, kem->length_ciphertext);

    printf("\n=== stage 2: AES-256-GCM encrypts the message ===\n");
    uint8_t iv[12], tag[16];
    if (RAND_bytes(iv, sizeof iv) != 1) { fprintf(stderr, "RAND failed\n"); return 1; }
    if (aes_gcm_encrypt(ss_enc, iv, kem_ct, kem->length_ciphertext,
                        (const uint8_t *)msg, msg_len, aes_ct, tag) != 0)
        return 1;
    hexdump("iv", iv, sizeof iv);
    hexdump("aes ciphertext", aes_ct, msg_len);
    hexdump("gcm tag", tag, sizeof tag);

    printf("\n=== stage 3: decrypt and verify ===\n");
    if (aes_gcm_decrypt(ss_enc, iv, kem_ct, kem->length_ciphertext,
                        aes_ct, msg_len, tag, pt) != 0)
        { fprintf(stderr, "clean decrypt failed\n"); return 1; }
    pt[msg_len] = '\0';
    printf("decrypted              : \"%s\"\n", pt);
    if (memcmp(pt, msg, msg_len) == 0)
        printf("[ok] roundtrip clean - hybrid encryption works end to end\n");
    else
        { printf("[FAIL] plaintext mismatch\n"); return 1; }

    printf("\n=== stage 4: tamper tests ===\n");
    aes_ct[0] ^= 0x01;   /* tamper with the file bytes */
    if (aes_gcm_decrypt(ss_enc, iv, kem_ct, kem->length_ciphertext,
                        aes_ct, msg_len, tag, pt) != 0)
        printf("[ok] tampered CIPHERTEXT rejected - GCM tag caught it\n");
    else
        { printf("[FAIL] tampered ct was accepted!\n"); return 1; }
    aes_ct[0] ^= 0x01;   /* restore */

    kem_ct[0] ^= 0x01;   /* tamper with the kyber envelope (AAD) instead */
    if (aes_gcm_decrypt(ss_enc, iv, kem_ct, kem->length_ciphertext,
                        aes_ct, msg_len, tag, pt) != 0)
        printf("[ok] tampered KEY ENVELOPE rejected - AAD binding caught it\n");
    else
        { printf("[FAIL] tampered AAD was accepted!\n"); return 1; }
    kem_ct[0] ^= 0x01;   /* restore */

    printf("\n[ok] hybrid pipeline complete: quantum-safe key delivery +\n");
    printf("     authenticated bulk encryption. this is the engine core.\n");

    OQS_MEM_cleanse(sk, kem->length_secret_key);
    OQS_MEM_cleanse(ss_enc, kem->length_shared_secret);
    OQS_MEM_cleanse(ss_dec, kem->length_shared_secret);
    OQS_MEM_cleanse(pt, msg_len);
    free(pk); free(sk); free(kem_ct); free(ss_enc); free(ss_dec);
    free(aes_ct); free(pt);
    OQS_KEM_free(kem);
    return 0;
}
