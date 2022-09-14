#ifndef _LIB_CRYPTO_CRYPTO_H_
#define _LIB_CRYPTO_CRYPTO_H_

/*******************************************************************************
 * Crypto Primitives
 ******************************************************************************/

//#ifdef _STD_LIBC_
//#include <crypto/mbedtls_import.h>
//#else
//#include <lib/crypto/mbedtls_import.h>
//#endif
#include <backend/mbedtls/include/mbedtls/ctr_drbg.h>
#include <backend/mbedtls/include/mbedtls/entropy.h>
#include <backend/mbedtls/include/mbedtls/sha256.h>
#include <backend/mbedtls/include/mbedtls/ecdsa.h>
#include <backend/mbedtls/include/mbedtls/ecdh.h>
#include <backend/mbedtls/include/mbedtls/chacha20.h>
#include <backend/mbedtls/include/mbedtls/chachapoly.h>
#include <backend/mbedtls/include/mbedtls/error.h>
#include <backend/mbedtls/include/mbedtls/memory_buffer_alloc.h>
#include <backend/mbedtls/include/mbedtls/base64.h>
#include <backend/mbedtls/include/mbedtls/pk.h>

#include <crypto/crypto_context.h>

typedef unsigned char* message_t;    /* plain text message */
typedef unsigned char* cyphertext_t; /* encrypted message */
typedef unsigned char* sk_t;         /* private key / symmetric key */

#define CRYPTO_DYNAMIC_MEMORY_SIZE (4096 * 100) /* 400KB */

/**
 * DRBG
 */
struct crypto_rng_context_t
{
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

/**
 * Secure Hash
 */
#define CRYPTO_HASH_SIZE (32)

typedef mbedtls_sha256_context crypto_hash_context_t;

/**
 * ECDS
 */
#define ECDS_CURVE_SPEC MBEDTLS_ECP_DP_SECP256R1

#define ECDS_SK_SIZE    (66)
#define ECDS_PK_SIZE    (2 * ECDS_SK_SIZE + 1)

struct crypto_ds_private_key_t
{
    unsigned char key[ECDS_SK_SIZE];
    size_t        len;
};

struct crypto_ds_public_key_t
{
    unsigned char key[ECDS_PK_SIZE];
    size_t        len;
};

struct crypto_ds_signature_t
{
    unsigned char signature[MBEDTLS_ECDSA_MAX_LEN];
    size_t        len;
};

struct crypto_ds_context_t
{
    mbedtls_sha256_context sha256_ctx;
    unsigned char          sha256_hash[32];

    mbedtls_ecdsa_context  ecdsa_ctx;
};

struct crypto_ds_certificate_t
{
    struct crypto_ds_public_key_t pk;
    struct crypto_ds_signature_t  sig;
};

struct crypto_pki_context_t
{
    struct crypto_ds_context_t*    authority;
    struct crypto_ds_context_t     client;
    struct crypto_ds_certificate_t cert;
};

/**
 * Key Exchange
 */
#define CRYPTO_DH_KEY_SIZE   (33)
#define CRYPTO_DH_CURVE_SIZE (36)

struct crypto_dh_context_t
{
    mbedtls_ecdh_context ecdh_ctx;
};

struct crypto_dh_curve_t
{
    unsigned char curve[CRYPTO_DH_CURVE_SIZE];
    size_t        len;
};

struct crypto_dh_key_t
{
    unsigned char key[CRYPTO_DH_KEY_SIZE];
    size_t        len;
};

/**
 * Stream Cipher
 */
struct crypto_sc_context_t
{
    mbedtls_chacha20_context chacha20;
    mbedtls_sha256_context   sha256_ctx;
    unsigned char            sha256_hash[32];
};

/**
 * Stream Cipher - with MAC
 */
struct crypto_sc_mac_context_t
{
    mbedtls_chachapoly_context chachapoly;
    mbedtls_sha256_context     sha256_ctx;
    unsigned char              sha256_hash[32];
    unsigned char              poly1305_tag[16];
};

/*******************************************************************************
 * crypto function declaration
 ******************************************************************************/
#define in
#define out

#define crypto_assert(expr)                                                    \
    do                                                                         \
    {                                                                          \
        if (!(expr))                                                           \
        {                                                                      \
            panic("assertion \"" #expr "\" failed in %s at %s:%d. abort!",     \
                __func__, __FILE__, __LINE__);                                 \
        }                                                                      \
    } while (0)

#ifdef __cplusplus
extern "C"
{
#endif

    void  crypto_init(void);

    /**
 * Key Generation
     */
    err_t crypto_rng(out unsigned char* output, in size_t output_len);

    /**
 * Base64
     */
    err_t crypto_b64_encode(unsigned char* dst, size_t dlen, size_t* olen,
        const unsigned char* src, size_t slen);

    err_t crypto_b64_decode(unsigned char* dst, size_t dlen, size_t* olen,
        const unsigned char* src, size_t slen);

    /**
 * Secure Hash
     */
    err_t crypto_hash_init(in crypto_hash_context_t* ctx);

    err_t crypto_hash_append(
        in crypto_hash_context_t* ctx, unsigned char* msg, size_t len);

    /* the size of result should be larger than 32 */
    err_t crypto_hash_report(
        in crypto_hash_context_t* ctx, unsigned char* result);

    /**
 * Digital Signature
     */
    err_t crypto_ds_init(in struct crypto_ds_context_t* ctx);

    err_t crypto_ds_gen_keypair(out struct crypto_ds_context_t* ctx);

    err_t crypto_ds_import_pem_keypair(in unsigned char* pem, in size_t pem_len,
        in unsigned char* passwd, in size_t passwd_len,
        out struct crypto_ds_context_t* key_ctx);

    err_t crypto_ds_import_pem_public_key(in unsigned char* pem,
        in size_t pem_len, out struct crypto_ds_context_t* key_ctx);

    err_t crypto_ds_export_pem_public_key(
        in struct crypto_ds_context_t* key_ctx, out unsigned char* pem,
        out size_t pem_len);

    err_t crypto_ds_export_public_key(in struct crypto_ds_context_t* ctx,
        out struct crypto_ds_public_key_t*                           pk);

    err_t crypto_ds_import_public_key(out struct crypto_ds_context_t* ctx,
        in struct crypto_ds_public_key_t*                             pk);

    err_t crypto_ds_export_private_key(in struct crypto_ds_context_t* ctx,
        out struct crypto_ds_private_key_t*                           sk);

    err_t crypto_ds_import_private_key(out struct crypto_ds_context_t* ctx,
        in struct crypto_ds_private_key_t*                             sk);

    void  crypto_ds_free(in struct crypto_ds_context_t* ctx);

    err_t crypto_sign_hashed(in struct crypto_ds_context_t* ctx,
        in unsigned char* sha256, out struct crypto_ds_signature_t* sig);

    err_t crypto_sign(in struct crypto_ds_context_t* ctx, in message_t msg,
        in size_t len, out struct crypto_ds_signature_t* sig);

    err_t crypto_verify_hashed(in struct crypto_ds_context_t* ctx,
        in unsigned char* sha256, in struct crypto_ds_signature_t* sig,
        out int* match);

    err_t crypto_verify(in struct crypto_ds_context_t* ctx, in message_t msg,
        in size_t len, in struct crypto_ds_signature_t* sig, out int* match);

    /**
 * PKI
     */
    err_t crypto_pki_new(in struct crypto_pki_context_t* ctx,
        in struct crypto_ds_context_t*                   authority);

    int  crypto_pki_verify(in struct crypto_pki_context_t* ctx);

    err_t crypto_pki_load_signature(in struct crypto_pki_context_t* ctx,
        in char* sig_b64, in size_t sig_len);

    /**
 * Key Exchange
     */
    err_t crypto_dh_genkey(in struct crypto_dh_context_t* ctx,
        out struct crypto_dh_curve_t*                     curve);

    err_t crypto_dh_exchange_genkey(in struct crypto_dh_context_t* ctx,
        in struct crypto_dh_curve_t* curve, out struct crypto_dh_key_t* shared,
        out struct crypto_dh_key_t* secrete);

    err_t crypto_dh_exchange(in struct crypto_dh_context_t* ctx,
        in struct crypto_dh_key_t* shared, out struct crypto_dh_key_t* secrete);

    /**
 * Stream Cipher
     */
    err_t crypto_sc_init(
        struct crypto_sc_context_t* ctx, sk_t sk, size_t sk_len);

    err_t crypto_sc_encrypt(in struct crypto_sc_context_t* ctx,
        in message_t msg, in size_t msg_len, out cyphertext_t ciphertext);

    err_t crypto_sc_decrypt(in struct crypto_sc_context_t* ctx,
        in cyphertext_t ciphertext, in size_t ciphertext_len,
        out message_t msg);

    /**
 * Stream Cipher - with MAC
     */
    err_t crypto_sc_mac_init(in struct crypto_sc_mac_context_t* ctx, in sk_t sk,
        in size_t sk_len, in int to_encrypt);

    err_t crypto_sc_mac_encrypt(in struct crypto_sc_mac_context_t* ctx,
        in message_t msg, in size_t msg_len, out cyphertext_t cipher_tag,
        out size_t* cipher_tag_len);

    int  crypto_sc_mac_decrypt(in struct crypto_sc_mac_context_t* ctx,
         in cyphertext_t cipher_tag, in size_t cipher_tag_len, out message_t msg,
         out size_t* msg_len);

#ifdef __cplusplus
}
#endif


#endif /* _LIB_CRYPTO_CRYPTO_H_ */
