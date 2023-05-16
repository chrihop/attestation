#ifndef _MBEDTLS_ABSTRACTION_H_
#define _MBEDTLS_ABSTRACTION_H_

#include <config.h>
#include <mbedtls/error.h>
#include <psa/crypto.h>
#include <primitives.h>

#define CRYPTO_ERROR_MSG_LEN (128u)

#ifdef __cplusplus
extern "C" {
#endif

    static inline void _mbedtls_panic(
        int error_code, const char* func, const char* file, const int line)
    {
        const char *high_level_error = NULL, *low_level_error = NULL;
        if (error_code < 0)
        {
            error_code = -error_code;
            if (error_code & 0xFF80)
            {
                high_level_error = mbedtls_high_level_strerr(error_code);
            }
            if (error_code & ~0xFF80)
            {
                low_level_error = mbedtls_low_level_strerr(error_code);
            }
        }
        PANIC(
            "fail to invoke the mbedtls library function (%s at %s:%d). error "
            "code -0x%x (%s : %s).\n",
            func, file, line, error_code,
            high_level_error ? high_level_error : "unknown",
            low_level_error ? low_level_error : "unknown");
    }

    const char *psa_strerror(int32_t status);

    static inline void _psa_panic(
        int error_code, const char* func, const char* file, const int line)
    {
        PANIC("fail to invoke the crypto library function (%s at %s:%d). error "
              "code -0x%x (%s).\n",
            func, file, line, -error_code, psa_strerror(error_code));
    }

#ifdef __cplusplus
};
#endif

#define mbedtls_call(func, ...)                                                 \
    do                                                                         \
    {                                                                          \
        int _rv = func(__VA_ARGS__);                                           \
        if (_rv != 0)                                                          \
        {                                                                      \
            _mbedtls_panic(_rv, #func, __FILE__, __LINE__);                     \
        }                                                                      \
    } while (0)

#define psa_call(func, ...)                                                    \
    do                                                                         \
    {                                                                          \
        psa_status_t _rv = func(__VA_ARGS__);                                  \
        if (_rv != PSA_SUCCESS)                                                \
        {                                                                      \
            _psa_panic(_rv, #func, __FILE__, __LINE__);                     \
        }                                                                      \
    } while (0)

#if __cplusplus
extern "C" {
#endif

/**
 * Key Generation
 */

typedef struct key
{
    psa_key_handle_t handle;
} key;

void crypto_rng(_out_ unsigned char* output, _in_ size_t output_len);


/**
 * Base64
 */
void
crypto_b64_encode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen);

void
crypto_b64_decode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen);

/**
 * Secure Hash
 */

/**
 * @brief
 * How to use secure hash:
 *   start -> append -> ... -> report
 * or
 *   start -> append -> ... -> verify
 */
typedef struct crypto_hash_context_t
{
    secure_hash_status_t status;
    psa_hash_operation_t * operation;
} crypto_hash_context_t;

#define CRYPTO_HASH_CONTEXT_INIT  {.status = SHS_NOT_STARTED}
#define CRYPTO_HASH_SIZE PSA_HASH_LENGTH(PSA_ALG_SHA_256)

void  crypto_hash_start(_in_out_ crypto_hash_context_t* ctx);
void  crypto_hash_append(_in_out_ crypto_hash_context_t* ctx,
     _in_ const unsigned char* input, _in_ size_t len);
void  crypto_hash_report(
     _in_out_ crypto_hash_context_t* ctx, _out_ uint8_t* output);
err_t crypto_hash_verify(
    _in_out_ crypto_hash_context_t* ctx, const _in_ uint8_t* hash);

/**
 * Symmetric Encryption (AEAD)
 */
typedef struct crypto_aead_context_t
{
    uint8_t has_key: 1;
    psa_key_handle_t key;
} crypto_aead_context_t;

#define CRYPTO_AEAD_CONTEXT_INIT  {.has_key = 0}

#define CRYPTO_AEAD_CIPHERTEXT_SIZE(plaintext_len)                             \
    PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_CHACHA20,                        \
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),       \
        (plaintext_len))

#define CRYPTO_AEAD_PLAINTEXT_SIZE(plaintext_len)                              \
    PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_CHACHA20,                        \
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),       \
        (plaintext_len))

#define CRYPTO_AEAD_NONCE_SIZE \
    PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305)

#define CRYPTO_AEAD_KEY_SIZE \
    PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_CHACHA20, 256)

void crypto_aead_encrypt(_in_out_ crypto_aead_context_t* ctx,
    const _in_ uint8_t* ad, _in_ size_t ad_len, const _in_ uint8_t* plaintext,
     _in_ size_t plaintext_len, _out_ uint8_t* ciphertext, _out_ uint8_t* nonce);

err_t crypto_aead_decrypt(_in_out_ crypto_aead_context_t* ctx,
    const _in_ uint8_t* ad, _in_ size_t ad_len, const _in_ uint8_t* ciphertext,
    _in_ size_t ciphertext_len, const _in_ uint8_t* nonce,
    _out_ uint8_t* plaintext);

void crypto_aead_peer(const _in_ crypto_aead_context_t* ctx, _out_ crypto_aead_context_t * peer);

void crypto_aead_init(_in_out_ crypto_aead_context_t * ctx);

void crypto_aead_free(_in_out_ crypto_aead_context_t * ctx);

void crypto_aead_export(_in_ crypto_aead_context_t * ctx, _out_ uint8_t * key);

void crypto_aead_import(
    _in_out_ crypto_aead_context_t * ctx, const _in_ uint8_t * key);

/**
 * Key Exchange
 */
typedef enum crypto_dh_step_t
{
    CRYPTO_DH_NOT_STARTED,
    CRYPTO_DH_PROPOSED,
    CRYPTO_DH_EXCHANGED,
} crypto_dh_step_t;


/**
 * @brief
 * How to use key exchange:
 *   A: propose()  -> A.pubkey
 *                    A.pubkey -> B: exchange_propose()
 *   A: exchange() <- B.pubkey <--+
 *   ---
 *   A: derive()   -> A.aead
 *                                B: derive() -> B.aead
 */
typedef struct crypto_dh_context_t
{
    crypto_dh_step_t step;
    psa_key_handle_t pair;
    psa_key_handle_t key;
} crypto_dh_context_t;

#define CRYPTO_DH_CONTEXT_INIT  {.step = CRYPTO_DH_NOT_STARTED}

/**
 * @note: curve25519 has half of the elliptic curve public key size
 */
#define CRYPTO_DH_PUBKEY_SIZE       32

static const char crypto_dh_default_info[] = "symmetric key";
#define CRYPTO_DH_INFO_SIZE (sizeof(crypto_dh_default_info) - 1)

void crypto_dh_propose(
    _in_out_ crypto_dh_context_t * ctx, _out_ uint8_t * pubkey);

void crypto_dh_exchange(
    _in_out_ crypto_dh_context_t * ctx, const _in_ uint8_t * pubkey);

void crypto_dh_exchange_propose(_in_out_ crypto_dh_context_t * ctx, const _in_ uint8_t * pubkey, _out_ uint8_t * out_pubkey);

void crypto_dh_derive_aead(
    _in_out_ crypto_dh_context_t * dh, _out_ crypto_aead_context_t * aead);

void crypto_dh_free(_in_out_ crypto_dh_context_t * ctx);

/**
 * Digital Signature
 */

/**
 * @brief
 * How to use digital signature:
 *   sign(keypair) -> signature
 *         +---> pubkey
 *        verify(pubkey, signature) -> true / false
 */
typedef struct crypto_ds_context_t
{
    uint8_t          has_key : 1;
    psa_key_handle_t key;
} crypto_ds_context_t;

#define CRYPTO_DS_CONTEXT_INIT                                                 \
    {                                                                          \
        .has_key = 0                                                           \
    }

#define __CRYPTO_DS_SIGNATURE_SIZE                                               \
    PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),    \
        256, PSA_ALG_ECDSA(PSA_ALG_SHA_256))

#define CRYPTO_DS_SIGNATURE_SIZE (64)

static_assert(CRYPTO_DS_SIGNATURE_SIZE == __CRYPTO_DS_SIGNATURE_SIZE,
    "CRYPTO_DS_SIGNATURE_SIZE missmatch");


#define CRYPTO_DS_KEY_SIZE    PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(256)

#define CRYPTO_DS_PUBKEY_SIZE PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)

void crypto_ds_sign(const _in_ crypto_ds_context_t * ctx, const _in_ uint8_t * msg, const _in_ size_t msg_len, _out_ uint8_t * signature);

err_t crypto_ds_verify(const _in_ crypto_ds_context_t* ctx, const _in_ uint8_t* msg, _in_ size_t msg_len, const _in_ uint8_t* signature);

void  crypto_ds_import(
    _in_out_ crypto_ds_context_t* ctx, const _in_ uint8_t* pem, size_t pem_len);

void crypto_ds_import_pubkey(
    _in_out_ crypto_ds_context_t* ctx, const _in_ uint8_t* pem, size_t pem_len);

void crypto_ds_import_pubkey_psa_format(
    _in_out_ crypto_ds_context_t* ctx, const _in_ uint8_t* pubkey);

void crypto_ds_export_pubkey(
    const _in_ crypto_ds_context_t * ctx, _out_ uint8_t * pubkey);

void crypto_ds_free(_in_out_ crypto_ds_context_t * ctx);

/**
 * Public Key Infrastructure
 */

/**
 * @brief How to use PKI:
 * device: load_root() -> root
 *     root -> endorse() -> key-pair, signature
 *     key-pair, signature -> verify() -> true / false
 */
typedef struct crypto_pki_context_t
{
    uint8_t is_root: 1;
    psa_key_handle_t parent;
    crypto_ds_context_t ds;
    uint8_t endorsement[CRYPTO_DS_SIGNATURE_SIZE];
} crypto_pki_context_t;

#define CRYPTO_PKI_CONTEXT_INIT                                                \
    {                                                                          \
        .ds = CRYPTO_DS_CONTEXT_INIT,                                          \
    }

typedef struct crypto_pki_certificate_t {
    uint8_t pubkey[CRYPTO_DS_PUBKEY_SIZE];
    uint8_t endorsement[CRYPTO_DS_SIGNATURE_SIZE];
} __attribute((packed)) crypto_pki_certificate_t;

void crypto_pki_load_root(void);

const crypto_pki_context_t * crypto_pki_root();

void crypto_pki_endorse(const _in_ crypto_pki_context_t * endorser,
     _in_out_ crypto_pki_context_t * endorsee);

err_t crypto_pki_verify(
    _in_ uint8_t * pubkey, _in_ uint8_t * identity, _in_ uint8_t * endorsement);

void crypto_pki_free(_in_out_ crypto_pki_context_t * ctx);

void crypto_pki_export_certificate(
    const _in_ crypto_pki_context_t * ctx, _out_ crypto_pki_certificate_t * cert);

/**
 * Global Context
 */
struct crypto_global_context_t
{
    psa_key_attributes_t aead_default;
    psa_key_attributes_t ds_default;
    psa_key_attributes_t ds_pubkey_default;
    psa_key_attributes_t dh_default;
    crypto_pki_context_t root;
};

#if __cplusplus
};
#endif



#endif /* _MBEDTLS_ABSTRACTION_H_ */
