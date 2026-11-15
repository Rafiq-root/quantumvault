/* qv_contract_test.c - pins the qv_crypto.h contract to the real liboqs
 *
 * rule: shared interfaces are frozen AND pinned. if liboqs ever changes
 * sizes or drops an algorithm, this fails loudly before any rust code
 * has been built on a broken assumption.
 */
#include <stdio.h>
#include <oqs/oqs.h>
#include "qv_crypto.h"

#define CHECK(expr) do { \
    if (!(expr)) { printf("[FAIL] %s\n", #expr); return 1; } \
    printf("[ok]   %s\n", #expr); \
} while (0)

int main(void)
{
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (!kem || !sig) {
        printf("[FAIL] ML-KEM-768 or ML-DSA-65 missing from liboqs build\n");
        return 1;
    }

    CHECK(kem->length_public_key    == QV_KEM_PK_BYTES);
    CHECK(kem->length_secret_key    == QV_KEM_SK_BYTES);
    CHECK(kem->length_ciphertext    == QV_KEM_CT_BYTES);
    CHECK(kem->length_shared_secret == QV_FILE_KEY_BYTES);
    CHECK(sig->length_public_key    == QV_SIG_PK_BYTES);
    CHECK(sig->length_secret_key    == QV_SIG_SK_BYTES);
    CHECK(sig->length_signature     == QV_SIG_MAX_BYTES);

    printf("\n[pinned] qv_crypto.h matches liboqs (f47aaf55).\n");
    printf("         rust side can bind these constants safely.\n");

    OQS_KEM_free(kem);
    OQS_SIG_free(sig);
    return 0;
}
