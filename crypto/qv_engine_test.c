/* qv_engine_test.c - full per-file lifecycle through the engine API
 *
 * this is the exact flow the vault runs for every file written:
 * wrap a fresh file key -> encrypt bytes (envelope as AAD) -> sign ->
 * then attack every layer and watch each rejection.
 *
 * this program is also the mid-review demo script.
 */
#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
#include "qv_crypto.h"

#define CHECK(expr) do { \
    if (!(expr)) { printf("[FAIL] %s\n", #expr); return 1; } \
    printf("[ok]   %s\n", #expr); \
} while (0)

int main(void)
{
    const char *msg = "quantumvault engine test - file bytes, nov 16";
    size_t msg_len = strlen(msg);

    uint8_t pk[QV_KEM_PK_BYTES],  sk[QV_KEM_SK_BYTES];
    uint8_t spk[QV_SIG_PK_BYTES], ssk[QV_SIG_SK_BYTES];
    uint8_t kem_ct[QV_KEM_CT_BYTES];
    uint8_t fk[QV_FILE_KEY_BYTES], fk2[QV_FILE_KEY_BYTES];
    uint8_t iv[QV_IV_BYTES], tag[QV_TAG_BYTES];
    uint8_t sig[QV_SIG_MAX_BYTES];
    size_t sig_len = 0;
    uint8_t ct[msg_len];
    uint8_t pt[msg_len + 1];

    printf("=== engine init ===\n");
    CHECK(qv_init() == QV_OK);

    printf("\n=== vault identity ===\n");
    CHECK(qv_kem_keypair(pk, sk) == QV_OK);
    CHECK(qv_sig_keypair(spk, ssk) == QV_OK);

    printf("\n=== per-file: wrap key, encrypt, sign ===\n");
    CHECK(qv_file_key_wrap(pk, kem_ct, fk) == QV_OK);
    CHECK(qv_encrypt(fk, kem_ct, QV_KEM_CT_BYTES,
                     (const uint8_t *)msg, msg_len, ct, iv, tag) == QV_OK);
    CHECK(qv_sign((const uint8_t *)msg, msg_len, ssk, sig, &sig_len) == QV_OK);
    printf("signature   : %zu bytes\n", sig_len);

    printf("\n=== read: decrypt, unwrap, verify ===\n");
    CHECK(qv_decrypt(fk, iv, kem_ct, QV_KEM_CT_BYTES,
                     ct, msg_len, tag, pt) == QV_OK);
    pt[msg_len] = '\0';
    CHECK(memcmp(pt, msg, msg_len) == 0);
    CHECK(qv_file_key_unwrap(kem_ct, sk, fk2) == QV_OK);
    CHECK(memcmp(fk, fk2, QV_FILE_KEY_BYTES) == 0);
    CHECK(qv_verify((const uint8_t *)msg, msg_len, sig, sig_len, spk) == QV_OK);

    printf("\n=== attacks: every layer must reject ===\n");
    ct[0] ^= 0x01;
    CHECK(qv_decrypt(fk, iv, kem_ct, QV_KEM_CT_BYTES,
                     ct, msg_len, tag, pt) == QV_ERR_CRYPTO);
    ct[0] ^= 0x01;

    tag[0] ^= 0x01;
    CHECK(qv_decrypt(fk, iv, kem_ct, QV_KEM_CT_BYTES,
                     ct, msg_len, tag, pt) == QV_ERR_CRYPTO);
    tag[0] ^= 0x01;

    kem_ct[0] ^= 0x01;   /* attack the key envelope itself */
    CHECK(qv_decrypt(fk, iv, kem_ct, QV_KEM_CT_BYTES,
                     ct, msg_len, tag, pt) == QV_ERR_CRYPTO);
    kem_ct[0] ^= 0x01;

    sig[0] ^= 0x01;
    CHECK(qv_verify((const uint8_t *)msg, msg_len, sig, sig_len, spk) == QV_ERR_CRYPTO);
    sig[0] ^= 0x01;

    printf("\n[ok] engine complete: every layer rejects its attack.\n");
    printf("     lifecycle proven - this is the vault's per-file flow.\n");

    OQS_MEM_cleanse(sk,  QV_KEM_SK_BYTES);
    OQS_MEM_cleanse(ssk, QV_SIG_SK_BYTES);
    OQS_MEM_cleanse(fk,  QV_FILE_KEY_BYTES);
    OQS_MEM_cleanse(fk2, QV_FILE_KEY_BYTES);
    qv_deinit();
    return 0;
}
