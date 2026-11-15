/* qv_crypto.h - QuantumVault crypto engine public contract
 *
 * frozen interface between the C engine and the rust side
 * (filesystem, key daemon, CLI). version 1 - nov 15 2026.
 *
 * FFI rules:
 *   - caller allocates and frees every buffer; the engine never mallocs
 *   - secret buffers (sk, file_key) belong to the caller; caller wipes
 *     (rust side: zeroize)
 *   - the engine generates IVs internally - callers cannot misuse GCM
 *   - sizes are FIPS 203/204 constants, pinned by qv_contract_test.c
 *
 * returns: QV_OK (0) on success, negative QV_ERR_* on failure.
 * qv_decrypt returns QV_ERR_CRYPTO on any tamper (tag mismatch).
 */
#ifndef QV_CRYPTO_H
#define QV_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---- status codes ---- */
#define QV_OK          0
#define QV_ERR_PARAM  -1   /* null pointer or zero length */
#define QV_ERR_CRYPTO -2   /* algorithm failure or tamper detected */
#define QV_ERR_OMEM   -3   /* out of memory (engine-internal temp) */

/* ---- algorithm sizes (FIPS 203 / FIPS 204) ---- */
#define QV_KEM_PK_BYTES    1184  /* ML-KEM-768 public key */
#define QV_KEM_SK_BYTES    2400  /* ML-KEM-768 secret key */
#define QV_KEM_CT_BYTES    1088  /* ML-KEM-768 ciphertext: wrapped file key */
#define QV_FILE_KEY_BYTES   32   /* KEM shared secret = AES-256 key */
#define QV_SIG_PK_BYTES    1952  /* ML-DSA-65 public key */
#define QV_SIG_SK_BYTES    4032  /* ML-DSA-65 secret key */
#define QV_SIG_MAX_BYTES   3309  /* ML-DSA-65 max signature */
#define QV_IV_BYTES          12  /* AES-256-GCM IV */
#define QV_TAG_BYTES         16  /* AES-256-GCM auth tag */

/* ---- lifecycle ---- */
int  qv_init(void);
void qv_deinit(void);   /* currently a no-op; reserved for engine state */

/* ---- key delivery: ML-KEM-768 ---- */
/* vault identity keypair; call once at vault creation */
int qv_kem_keypair(uint8_t pk[QV_KEM_PK_BYTES],
                   uint8_t sk[QV_KEM_SK_BYTES]);

/* per file: encapsulate a fresh random file key to the vault public key.
 * outputs kem_ct (goes in the file header) + file_key (drives AES).
 * call once per file write. */
int qv_file_key_wrap(const uint8_t pk[QV_KEM_PK_BYTES],
                     uint8_t kem_ct[QV_KEM_CT_BYTES],
                     uint8_t file_key[QV_FILE_KEY_BYTES]);

/* on read: recover the file key from the envelope with the vault secret key */
int qv_file_key_unwrap(const uint8_t kem_ct[QV_KEM_CT_BYTES],
                       const uint8_t sk[QV_KEM_SK_BYTES],
                       uint8_t file_key[QV_FILE_KEY_BYTES]);

/* ---- bulk encryption: AES-256-GCM, engine-generated IV ---- */
/* ct must have room for pt_len bytes. aad may be NULL (aad_len 0). */
int qv_encrypt(const uint8_t file_key[QV_FILE_KEY_BYTES],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *pt, size_t pt_len,
               uint8_t *ct,
               uint8_t iv[QV_IV_BYTES],
               uint8_t tag[QV_TAG_BYTES]);

/* QV_OK only if the tag verifies; tampered ct, tag, or aad -> QV_ERR_CRYPTO */
int qv_decrypt(const uint8_t file_key[QV_FILE_KEY_BYTES],
               const uint8_t iv[QV_IV_BYTES],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *ct, size_t ct_len,
               const uint8_t tag[QV_TAG_BYTES],
               uint8_t *pt);

/* ---- file proofs: ML-DSA-65 ---- */
int qv_sig_keypair(uint8_t pk[QV_SIG_PK_BYTES],
                   uint8_t sk[QV_SIG_SK_BYTES]);

/* sig must have room for QV_SIG_MAX_BYTES; *sig_len gets the real length */
int qv_sign(const uint8_t *msg, size_t msg_len,
            const uint8_t sk[QV_SIG_SK_BYTES],
            uint8_t *sig, size_t *sig_len);

int qv_verify(const uint8_t *msg, size_t msg_len,
              const uint8_t *sig, size_t sig_len,
              const uint8_t pk[QV_SIG_PK_BYTES]);

#endif /* QV_CRYPTO_H */
