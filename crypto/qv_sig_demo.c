/* qv_sig_demo.c - QuantumVault crypto engine, step 3: signatures
 *
 * proves the ML-DSA-65 (dilithium) pattern:
 *   keypair -> sign a message -> verify (ok)
 *   forge test 1: tampered message   -> verify must FAIL
 *   forge test 2: tampered signature -> verify must FAIL
 *   forge test 3: wrong public key   -> verify must FAIL (authenticity:
 *   nobody else can claim they signed this file)
 *
 * in the vault: the engine signs every file's header, so any later
 * modification is detectable and the author is provable.
 *
 * API (liboqs f47aaf55): OQS_init() void, sig->method_name,
 * OQS_SIG_sign writes the real length via sig_len (ML-DSA signatures
 * vary a bit around the max).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (sig == NULL) {
        fprintf(stderr, "ML-DSA-65 not enabled in this liboqs build\n");
        return 1;
    }
    printf("algorithm   : %s\n", sig->method_name);
    printf("sizes       : pk=%zu  sk=%zu  sig_max=%zu\n\n",
           sig->length_public_key, sig->length_secret_key,
           sig->length_signature);

    const char *msg = "quantumvault design notes v1 - author: rafael";
    size_t msg_len = strlen(msg);

    uint8_t *pk  = malloc(sig->length_public_key);
    uint8_t *sk  = malloc(sig->length_secret_key);
    uint8_t *sg  = malloc(sig->length_signature);
    uint8_t *pk2 = malloc(sig->length_public_key);
    uint8_t *sk2 = malloc(sig->length_secret_key);
    uint8_t *tam = malloc(msg_len);
    if (!pk || !sk || !sg || !pk2 || !sk2 || !tam) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    /* the vault's identity keypair */
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "keypair failed\n"); return 1;
    }
    hexdump("public key", pk, sig->length_public_key);

    /* sign the message; real signature length comes back in sig_len */
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, sg, &sig_len, (const uint8_t *)msg, msg_len, sk)
        != OQS_SUCCESS) {
        fprintf(stderr, "sign failed\n"); return 1;
    }
    printf("signature   : %zu bytes (max was %zu)\n", sig_len,
           sig->length_signature);
    hexdump("signature", sg, sig_len);

    /* genuine pair verifies */
    if (OQS_SIG_verify(sig, (const uint8_t *)msg, msg_len, sg, sig_len, pk)
        == OQS_SUCCESS)
        printf("\n[ok] genuine message + signature verify\n");
    else { printf("\n[FAIL] genuine pair rejected\n"); return 1; }

    /* forge 1: attacker edits the file after it was signed */
    memcpy(tam, msg, msg_len);
    tam[0] ^= 0x01;   /* "Cuantumvault..." */
    if (OQS_SIG_verify(sig, tam, msg_len, sg, sig_len, pk) != OQS_SUCCESS)
        printf("[ok] tampered MESSAGE rejected\n");
    else { printf("[FAIL] tampered message accepted!\n"); return 1; }

    /* forge 2: attacker tweaks the signature bytes */
    sg[0] ^= 0x01;
    if (OQS_SIG_verify(sig, (const uint8_t *)msg, msg_len, sg, sig_len, pk)
        != OQS_SUCCESS)
        printf("[ok] tampered SIGNATURE rejected\n");
    else { printf("[FAIL] tampered signature accepted!\n"); return 1; }
    sg[0] ^= 0x01;   /* restore */

    /* forge 3: a different signer's key tries to claim the file */
    if (OQS_SIG_keypair(sig, pk2, sk2) != OQS_SUCCESS) return 1;
    if (OQS_SIG_verify(sig, (const uint8_t *)msg, msg_len, sg, sig_len, pk2)
        != OQS_SUCCESS)
        printf("[ok] WRONG SIGNER's key rejected - authorship is provable\n");
    else { printf("[FAIL] foreign key accepted!\n"); return 1; }

    printf("\n[ok] signatures done: integrity + authenticity for every\n");
    printf("     vault file. engine now has all three pillars:\n");
    printf("     kyber (keys) + AES-GCM (bytes) + dilithium (proof)\n");

    OQS_MEM_cleanse(sk,  sig->length_secret_key);
    OQS_MEM_cleanse(sk2, sig->length_secret_key);
    free(pk); free(sk); free(sg); free(pk2); free(sk2); free(tam);
    OQS_SIG_free(sig);
    return 0;
}
