/* qv_kem_demo.c - QuantumVault crypto engine, step 1
 *
 * proves the ML-KEM-768 (Kyber768) roundtrip:
 *   keypair -> encapsulate against the public key -> decapsulate with
 *   the secret key -> both sides hold the same 32-byte shared secret.
 *
 * in the real engine this shared secret wraps the per-file AES key
 * (hybrid encryption: post-quantum KEM for key agreement, AES for bulk data).
 *
 * API notes for this liboqs build (commit f47aaf55):
 *   OQS_init() returns void; the KEM struct exposes method_name;
 *   there is no OQS_exit() in this version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

static void hexdump(const char *label, const uint8_t *buf, size_t n)
{
    printf("%-14s (%zu bytes): ", label, n);
    for (size_t i = 0; i < n && i < 16; i++)
        printf("%02x", buf[i]);
    if (n > 16) printf("...");
    printf("\n");
}

int main(void)
{
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (kem == NULL) {
        fprintf(stderr, "ML-KEM-768 not enabled in this liboqs build\n");
        return 1;
    }
    printf("algorithm     : %s\n", kem->method_name);
    printf("sizes         : pk=%zu  sk=%zu  ct=%zu  ss=%zu\n\n",
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);

    uint8_t *pk     = malloc(kem->length_public_key);
    uint8_t *sk     = malloc(kem->length_secret_key);
    uint8_t *ct     = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);
    if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    /* side A: generate the long-term keypair */
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    hexdump("public key", pk, kem->length_public_key);
    hexdump("secret key", sk, kem->length_secret_key);

    /* side B: encapsulate against the public key */
    if (OQS_KEM_encaps(kem, ct, ss_enc, pk) != OQS_SUCCESS) {
        fprintf(stderr, "encapsulation failed\n");
        return 1;
    }
    hexdump("ciphertext", ct, kem->length_ciphertext);
    hexdump("shared secret", ss_enc, kem->length_shared_secret);

    /* side A: decapsulate the ciphertext with the secret key */
    if (OQS_KEM_decaps(kem, ss_dec, ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "decapsulation failed\n");
        return 1;
    }

    if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0) {
        printf("\n[ok] both sides derived the SAME shared secret\n");
        printf("[ok] kyber roundtrip works - this is the envelope QuantumVault\n");
        printf("     will use to wrap every per-file AES key\n");
    } else {
        printf("\n[FAIL] secrets differ - something is broken\n");
        return 1;
    }

    /* hygienic exit: wipe secrets before free, like the real engine will */
    OQS_MEM_cleanse(sk,     kem->length_secret_key);
    OQS_MEM_cleanse(ss_enc, kem->length_shared_secret);
    OQS_MEM_cleanse(ss_dec, kem->length_shared_secret);
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    OQS_KEM_free(kem);
    return 0;
}
