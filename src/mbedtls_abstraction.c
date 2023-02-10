#include <psa/crypto.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/base64.h>
#include <mbedtls_abstraction.h>
#include <mbedtls/platform.h>

#include <primitives.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_ENTROPY_LEN (32u)
static char crypto_entropy_source[]
    = "2s5v8y/B?E(H+MbQeThWmYq3t6w9z$C&F)J@NcRfUjXn2r4u7x!A%D*G-KaPdSgV"
      "jXn2r5u8x/A?D(G+KbPeShVmYp3s6v9y$B&E)H@McQfTjWnZr4t7w!z%C*F-JaNd"
      "RfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)J"
      "@McQfThWmZq4t7w!z%C*F-JaNdRgUkXn2r5u8x/A?D(G+KbPeShVmYq3s6v9y$B&"
      "E(H+MbQeThVmYq3t6w9z$C&F)J@NcRfUjXnZr4u7x!A%D*G-KaPdSgVkYp3s5v8y"
      "/A?D(G+KbPeShVkYp3s6v9y$B&E)H@McQfTjWnZq4t7w!z%C*F-JaNdRgUkXp2s5"
      "u7x!A%D*G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThWmYq3t6w9z$C&F)J@NcRfUjXn"
      "Zq4t7w!z%C*F-JaNdRgUjXn2r5u8x/A?D(G+KbPeShVmYp3s6v9y$B&E)H@McQfT"
      "hVmYq3t6w9z$C&F)J@NcRfUjWnZr4u7x!A%D*G-KaPdSgVkYp2s5v8y/B?E(H+Mb"
      "PeSgVkYp3s6v9y$B&E)H@McQfTjWmZq4t7w!z%C*F-JaNdRgUkXp2r5u8x/A?D(G"
      "-KaPdRgUkXp2s5v8y/B?E(H+MbQeThWmYq3t6w9z$C&F)J@NcRfUjXn2r4u7x!A%"
      "C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp3s6v9y$B&E)H@McQfTjWnZq4t7w"
      "9z$C&F)J@NcRfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+MbQeThWmZq3"
      "s6v9y$B&E)H@McQfThWmZq4t7w!z%C*F-JaNdRgUkXn2r5u8x/A?D(G+KbPeShVm"
      "Xp2s5v8y/B?E(H+MbQeThVmYq3t6w9z$C&F)J@NcRfUjXnZr4u7x!A%D*G-KaPdS"
      "fUjXn2r5u8x/A?D(G+KbPeSgVkYp3s6v9y$B&E)H@McQfTjWmZq4t7w!z%C*F-Ja"
      "NcQfTjWnZr4u7x!A%D*G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThWmYq3t6w9z$C&F"
      "x)H@McQeThWmZq4t7w!z%C*F-JaNdRgUjXn2r5u8x/A?D(G+KbPeShVmYp3s6v9y"
      "B?E(H+MbQeShVmYq3t6w9z$C&F)J@NcRfUjWnZr4u7x!A%D*G-KaPdSgVkYp2s5v"
      "8x/A?D(G+KbPdSgVkYp3s6v9y$B&E)H@McQfThWmZq4t7w!z%C*F-JaNdRgUkXp2"
      "r4u7x!A%D*G-KaPdRgUkXp2s5v8y/B?E(H+MbQeThVmYq3t6w9z$C&F)J@NcRfUj"
      "WmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp3s6v9y$B&E)H@McQ"
      "eShVmYq3t6w9z$C&F)J@NcRfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+"
      "KaPdSgVkYp3s6v9y$B&E)H@McQfThWmZq4t7w!z%C*F-JaNdRgUkXn2r5u8x/A?D"
      "*G-KaNdRgUkXp2s5v8y/B?E(H+MbQeShVmYq3t6w9z$C&F)J@NcRfUjWnZr4u7x!";

static size_t pseudo_entropy_counter = 32;
static int
pseudo_entropy_source(
    void* data, unsigned char* output, size_t len, size_t* olen)
{
    size_t n    = sizeof(crypto_entropy_source);
    size_t left = n - pseudo_entropy_counter;
    __builtin_memcpy(output, crypto_entropy_source, left < len ? left : len);
    if (left < len)
    {
        __builtin_memset(&output[left], 0xa4, n - left);
    }
    *olen                  = len;
    pseudo_entropy_counter = (pseudo_entropy_counter + len) % n;
    return 0;
}

struct crypto_rng_context_t
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

static struct crypto_rng_context_t crypto_drbg;

static void
    pseudo_get_random(unsigned char* output, size_t len)
{
    mbedtls_call(mbedtls_ctr_drbg_random, &crypto_drbg.ctr_drbg, output, len);
}

static unsigned char crypto_dynamic_memory[DYNAMIC_MEMORY_SIZE]
    __attribute__((aligned(32)));

static inline int is_allocated(void* ptr)
{
    return (uintptr_t)ptr >= (uintptr_t)crypto_dynamic_memory
        && (uintptr_t)ptr
        < (uintptr_t)crypto_dynamic_memory + DYNAMIC_MEMORY_SIZE;
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void)context;
    *output_length = output_size;
    pseudo_get_random(output, output_size);
    return PSA_SUCCESS;
}

/**
 * @brief copied from build/psa_constant_names_generated.c
 * @param status
 * @return
 */
const char *psa_strerror(int32_t status)
{
    switch (status) {
    case PSA_ERROR_ALREADY_EXISTS: return "PSA_ERROR_ALREADY_EXISTS";
    case PSA_ERROR_BAD_STATE: return "PSA_ERROR_BAD_STATE";
    case PSA_ERROR_BUFFER_TOO_SMALL: return "PSA_ERROR_BUFFER_TOO_SMALL";
    case PSA_ERROR_COMMUNICATION_FAILURE: return "PSA_ERROR_COMMUNICATION_FAILURE";
    case PSA_ERROR_CORRUPTION_DETECTED: return "PSA_ERROR_CORRUPTION_DETECTED";
    case PSA_ERROR_DATA_CORRUPT: return "PSA_ERROR_DATA_CORRUPT";
    case PSA_ERROR_DATA_INVALID: return "PSA_ERROR_DATA_INVALID";
    case PSA_ERROR_DOES_NOT_EXIST: return "PSA_ERROR_DOES_NOT_EXIST";
    case PSA_ERROR_GENERIC_ERROR: return "PSA_ERROR_GENERIC_ERROR";
    case PSA_ERROR_HARDWARE_FAILURE: return "PSA_ERROR_HARDWARE_FAILURE";
    case PSA_ERROR_INSUFFICIENT_DATA: return "PSA_ERROR_INSUFFICIENT_DATA";
    case PSA_ERROR_INSUFFICIENT_ENTROPY: return "PSA_ERROR_INSUFFICIENT_ENTROPY";
    case PSA_ERROR_INSUFFICIENT_MEMORY: return "PSA_ERROR_INSUFFICIENT_MEMORY";
    case PSA_ERROR_INSUFFICIENT_STORAGE: return "PSA_ERROR_INSUFFICIENT_STORAGE";
    case PSA_ERROR_INVALID_ARGUMENT: return "PSA_ERROR_INVALID_ARGUMENT";
    case PSA_ERROR_INVALID_HANDLE: return "PSA_ERROR_INVALID_HANDLE";
    case PSA_ERROR_INVALID_PADDING: return "PSA_ERROR_INVALID_PADDING";
    case PSA_ERROR_INVALID_SIGNATURE: return "PSA_ERROR_INVALID_SIGNATURE";
    case PSA_ERROR_NOT_PERMITTED: return "PSA_ERROR_NOT_PERMITTED";
    case PSA_ERROR_NOT_SUPPORTED: return "PSA_ERROR_NOT_SUPPORTED";
    case PSA_ERROR_STORAGE_FAILURE: return "PSA_ERROR_STORAGE_FAILURE";
    case PSA_SUCCESS: return "PSA_SUCCESS";
    default: return NULL;
    }
}

static struct crypto_global_context_t crypto_global = {
    .aead_default = PSA_KEY_ATTRIBUTES_INIT,
    .ds_default   = PSA_KEY_ATTRIBUTES_INIT,
    .ds_pubkey_default = PSA_KEY_ATTRIBUTES_INIT,
    .dh_default   = PSA_KEY_ATTRIBUTES_INIT,
    .root = CRYPTO_PKI_CONTEXT_INIT,
};

static void crypto_global_init()
{
    crypto_global.aead_default = psa_key_attributes_init();
    psa_set_key_usage_flags(&crypto_global.aead_default,
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&crypto_global.aead_default,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305));
    psa_set_key_type(&crypto_global.aead_default, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&crypto_global.aead_default, 256);

    crypto_global.ds_default = psa_key_attributes_init();
    psa_set_key_usage_flags(&crypto_global.ds_default,
        PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&crypto_global.ds_default,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&crypto_global.ds_default,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    psa_set_key_bits(&crypto_global.ds_default, 256);

    crypto_global.ds_pubkey_default = psa_key_attributes_init();
    psa_set_key_usage_flags(&crypto_global.ds_pubkey_default,
        PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&crypto_global.ds_pubkey_default,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&crypto_global.ds_pubkey_default,
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1));

    crypto_global.dh_default = psa_key_attributes_init();
    psa_set_key_usage_flags(&crypto_global.dh_default,
        PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&crypto_global.dh_default,
        PSA_ALG_ECDH);
    psa_set_key_type(&crypto_global.dh_default,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&crypto_global.dh_default, 255);
}

void
crypto_init(void)
{
    /* allocator */
    mbedtls_memory_buffer_alloc_init(
        crypto_dynamic_memory, DYNAMIC_MEMORY_SIZE);

    /* mutex */
    mbedtls_threading_set_alt(
        crypto_mutex_init,
        crypto_mutex_free,
        crypto_mutex_lock,
        crypto_mutex_unlock
        );

    /* platform primitives */
    mbedtls_platform_set_snprintf(crypto_snprintf);
    mbedtls_platform_set_vsnprintf(crypto_vsnprintf);
    mbedtls_platform_set_printf(crypto_printf);
    mbedtls_platform_set_fprintf(crypto_fprintf);
    mbedtls_platform_set_setbuf(crypto_setbuf);
    mbedtls_platform_set_exit(crypto_exit);

    /* drbg */
    mbedtls_ctr_drbg_init(&crypto_drbg.ctr_drbg);
    mbedtls_entropy_init(&crypto_drbg.entropy);
    mbedtls_entropy_add_source(
        &crypto_drbg.entropy, pseudo_entropy_source, NULL, 32, 1);

    mbedtls_call(mbedtls_ctr_drbg_seed, &crypto_drbg.ctr_drbg,
        mbedtls_entropy_func, &crypto_drbg.entropy,
        (const unsigned char*)crypto_entropy_source, CRYPTO_ENTROPY_LEN);

    /* psa */
    psa_call(psa_crypto_init);

    /* global */
    crypto_global_init();

    /* pki */
    crypto_global.root.ds.has_key = 0;
    crypto_pki_load_root();
}

/**
 * Key Generation
 */
void
crypto_rng(out unsigned char* output, in size_t output_len)
{
    crypto_assert(output != NULL);
    psa_call(psa_generate_random, output, output_len);
}

/**
 * Base64
 */
void
crypto_b64_encode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen)
{
    crypto_assert(dst != NULL);
    crypto_assert(olen != NULL);
    crypto_assert(src != NULL);
    mbedtls_call(mbedtls_base64_encode, dst, dlen, olen, src, slen);
}

void
crypto_b64_decode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen)
{
    crypto_assert(dst != NULL);
    crypto_assert(olen != NULL);
    crypto_assert(src != NULL);
    mbedtls_call(mbedtls_base64_decode, dst, dlen, olen, src, slen);
}

/**
 * Secure Hash
 */
void
crypto_hash_start(in_out crypto_hash_context_t * ctx)
{
    crypto_assert(ctx != NULL);
    if (ctx->status == SHS_IN_PROGRESS && ctx->operation != NULL && is_allocated(ctx->operation))
    {
        psa_call(psa_hash_abort, ctx->operation);
    }
    else
    {
        ctx->operation = mbedtls_calloc(1, sizeof(psa_hash_operation_t));
    }
    psa_call(psa_hash_setup, ctx->operation, PSA_ALG_SHA_256);
    ctx->status = SHS_IN_PROGRESS;
}

void
crypto_hash_append(in_out crypto_hash_context_t * ctx,
    in const unsigned char *input, in size_t len)
{
    crypto_assert(ctx != NULL);
    crypto_assert(input != NULL);
    psa_call(psa_hash_update, ctx->operation, input, len);
}

void
crypto_hash_report(in_out crypto_hash_context_t * ctx,
    out uint8_t * output)
{
    crypto_assert(ctx != NULL);
    crypto_assert(output != NULL);

    size_t olen = 0;
    psa_call(psa_hash_finish, ctx->operation, output, HASH_OUTPUT_SIZE, &olen);
    crypto_assert(olen == HASH_OUTPUT_SIZE);
    ctx->status = SHS_DONE;
    psa_hash_abort(ctx->operation);
    mbedtls_free(ctx->operation);
    ctx->operation = NULL;
}

err_t
crypto_hash_verify(in_out crypto_hash_context_t * ctx,
    in const uint8_t * hash)
{
    crypto_assert(ctx != NULL);
    crypto_assert(hash != NULL);

    psa_status_t status;
    status = psa_hash_verify(ctx->operation, hash, HASH_OUTPUT_SIZE);
    ctx->status = SHS_DONE;
    psa_hash_abort(ctx->operation);
    mbedtls_free(ctx->operation);
    ctx->operation = NULL;
    return status == PSA_SUCCESS ? ERR_OK : ERR_VERIFICATION_FAILED;
}

/**
 * Symmetric Stream Cipher (AEAD)
 */

static void crypto_aead_keygen(in_out crypto_aead_context_t * ctx)
{
    psa_call(psa_generate_key, &crypto_global.aead_default, &ctx->key);
    ctx->has_key = 1;
}

void crypto_aead_init(in_out crypto_aead_context_t * ctx)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->key == 0);

    crypto_aead_keygen(ctx);
}

/**
 * encrypt the plaintext
 * (ad :: plaintext) -> (nonce, ciphertext :: tag)
 *
 * use nonce + key to decrypt
 * use tag to verify (ad :: plaintext)
 */
void crypto_aead_encrypt(
    in_out crypto_aead_context_t * ctx,
    in const uint8_t * ad, in size_t ad_len,
    in const uint8_t * plaintext, in size_t plaintext_len,
    out uint8_t * ciphertext,
    out uint8_t * nonce)
{
    crypto_assert(ctx != NULL);
    crypto_assert(plaintext != NULL);
    crypto_assert(ciphertext != NULL);
    crypto_assert(nonce != NULL);

    if (! ctx->has_key)
    {
        crypto_aead_keygen(ctx);
    }

    psa_call(psa_generate_random, nonce, CRYPTO_AEAD_NONCE_SIZE);

    size_t olen = 0;
    psa_call(psa_aead_encrypt, ctx->key,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
        nonce, CRYPTO_AEAD_NONCE_SIZE,
        ad, ad_len,
        plaintext, plaintext_len,
        ciphertext, CRYPTO_AEAD_CIPHERTEXT_SIZE(plaintext_len), &olen);
    crypto_assert(olen == CRYPTO_AEAD_CIPHERTEXT_SIZE(plaintext_len));
}

/**
 * decrypt the ciphertext
 * (nonce, ad :: ciphertext :: tag) -> (plaintext, verified?)
 */
err_t
crypto_aead_decrypt(
    in_out crypto_aead_context_t * ctx,
    in const uint8_t * ad, in size_t ad_len,
    in const uint8_t * ciphertext, in size_t ciphertext_len,
    in const uint8_t * nonce,
    out uint8_t * plaintext)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ciphertext != NULL);
    crypto_assert(plaintext != NULL);
    crypto_assert(nonce != NULL);

    if (! ctx->has_key)
    {
        crypto_aead_keygen(ctx);
    }

    size_t olen = 0;
    psa_status_t status = psa_aead_decrypt(ctx->key,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
        nonce, CRYPTO_AEAD_NONCE_SIZE,
        ad, ad_len,
        ciphertext, ciphertext_len,
        plaintext, ciphertext_len, &olen);
    return status == PSA_SUCCESS ? ERR_OK : ERR_VERIFICATION_FAILED;
}

void crypto_aead_peer(in crypto_aead_context_t* ctx,
    out crypto_aead_context_t * peer)
{
    if (peer->has_key)
    {
        psa_destroy_key(peer->key);
    }

    psa_call(psa_copy_key, ctx->key, &crypto_global.aead_default, &peer->key);
    peer->has_key = 1;
}

void crypto_aead_free(in_out crypto_aead_context_t * ctx)
{
    crypto_assert(ctx != NULL);
    if (ctx->has_key)
    {
        psa_destroy_key(ctx->key);
    }
    ctx->has_key = 0;
}

void crypto_aead_export(in crypto_aead_context_t * ctx, out uint8_t * key)
{
    crypto_assert(ctx != NULL);
    crypto_assert(key != NULL);
    size_t olen = 0;
    psa_call(psa_export_key, ctx->key, key, CRYPTO_AEAD_KEY_SIZE, &olen);
    crypto_assert(olen == CRYPTO_AEAD_KEY_SIZE);
}

void crypto_aead_import(in_out crypto_aead_context_t * ctx, in const uint8_t * key)
{
    crypto_assert(ctx != NULL);
    crypto_assert(key != NULL);

    if (ctx->has_key)
    {
        psa_destroy_key(ctx->key);
    }
    psa_call(psa_import_key, &crypto_global.aead_default, key, CRYPTO_AEAD_KEY_SIZE, &ctx->key);
    ctx->has_key = 1;
}

/**
 * Key Exchange
 */

void crypto_dh_propose(in_out crypto_dh_context_t * ctx, out uint8_t * pubkey)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == CRYPTO_DH_NOT_STARTED);
    crypto_assert(pubkey != NULL);

    size_t olen = 0;
    psa_call(psa_generate_key, &crypto_global.dh_default, &ctx->pair);
    psa_call(psa_export_public_key, ctx->pair, pubkey, CRYPTO_DH_PUBKEY_SIZE, &olen);
    crypto_assert(olen == CRYPTO_DH_PUBKEY_SIZE);
    ctx->step = CRYPTO_DH_PROPOSED;
}

void crypto_dh_exchange(in_out crypto_dh_context_t * ctx, in uint8_t * pubkey)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == CRYPTO_DH_PROPOSED);
    crypto_assert(pubkey != NULL);

    psa_key_derivation_operation_t * op = mbedtls_calloc(1, sizeof(psa_key_derivation_operation_t));
    psa_call(psa_key_derivation_setup, op,
        PSA_ALG_KEY_AGREEMENT(
            PSA_ALG_ECDH,
            PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)));
    psa_call(psa_key_derivation_key_agreement,
        op,
        PSA_KEY_DERIVATION_INPUT_SECRET,
        ctx->pair,
        pubkey,
        CRYPTO_DH_PUBKEY_SIZE);

    psa_call(psa_key_derivation_input_bytes,
        op,
        PSA_KEY_DERIVATION_INPUT_INFO,
        (const uint8_t *) crypto_dh_default_info,
        CRYPTO_DH_INFO_SIZE);
    psa_call(psa_key_derivation_output_key,
        &crypto_global.aead_default,
        op,
        &ctx->key);
    psa_key_derivation_abort(op);
    psa_call(psa_destroy_key, ctx->pair);
    mbedtls_free(op);
    ctx->step = CRYPTO_DH_EXCHANGED;
}

void crypto_dh_exchange_propose(in_out crypto_dh_context_t * ctx, in uint8_t * pubkey, out uint8_t * out_pubkey)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == CRYPTO_DH_NOT_STARTED);
    crypto_assert(pubkey != NULL);
    crypto_assert(out_pubkey != NULL);

    size_t olen = 0;
    psa_call(psa_generate_key, &crypto_global.dh_default, &ctx->pair);
    psa_call(psa_export_public_key, ctx->pair, out_pubkey, CRYPTO_DH_PUBKEY_SIZE, &olen);
    crypto_assert(olen == CRYPTO_DH_PUBKEY_SIZE);
    psa_key_derivation_operation_t * op = mbedtls_calloc(1, sizeof(psa_key_derivation_operation_t));
    psa_call(psa_key_derivation_setup, op,
        PSA_ALG_KEY_AGREEMENT(
            PSA_ALG_ECDH,
            PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)));
    psa_call(psa_key_derivation_key_agreement,
        op,
        PSA_KEY_DERIVATION_INPUT_SECRET,
        ctx->pair,
        pubkey,
        CRYPTO_DH_PUBKEY_SIZE);
    psa_call(psa_key_derivation_input_bytes,
        op,
        PSA_KEY_DERIVATION_INPUT_INFO,
        (const uint8_t *) crypto_dh_default_info,
        CRYPTO_DH_INFO_SIZE);
    psa_call(psa_key_derivation_output_key,
        &crypto_global.aead_default,
        op,
        &ctx->key);
    psa_key_derivation_abort(op);
    psa_call(psa_destroy_key, ctx->pair);
    mbedtls_free(op);
    ctx->step = CRYPTO_DH_EXCHANGED;
}

void crypto_dh_derive_aead(in_out crypto_dh_context_t * dh, out crypto_aead_context_t * aead)
{
    crypto_assert(dh != NULL);
    crypto_assert(dh->step == CRYPTO_DH_EXCHANGED);
    crypto_assert(aead != NULL);

    if (aead->has_key)
    {
        psa_call(psa_destroy_key, aead->key);
    }
    psa_call(psa_copy_key, dh->key, &crypto_global.aead_default, &aead->key);
    psa_call(psa_destroy_key, dh->key);
    aead->has_key = 1;
    dh->step = CRYPTO_DH_NOT_STARTED;
}

void crypto_dh_free(in_out crypto_dh_context_t * ctx)
{
    crypto_assert(ctx != NULL);

    if (ctx->step == CRYPTO_DH_EXCHANGED)
    {
        psa_call(psa_destroy_key, ctx->key);
    }
    else if (ctx->step == CRYPTO_DH_PROPOSED)
    {
        psa_call(psa_destroy_key, ctx->pair);
    }
    ctx->step = CRYPTO_DH_NOT_STARTED;
}

/**
 * Digital Signature
 */

void crypto_ds_free(in_out crypto_ds_context_t * ctx)
{
    crypto_assert(ctx != NULL);

    if (ctx->has_key)
    {
        psa_call(psa_destroy_key, ctx->key);
    }
    ctx->has_key = 0;
}

void crypto_ds_sign(in const crypto_ds_context_t * ctx, in uint8_t * msg, in size_t msg_len,
    out uint8_t * signature)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->has_key);
    crypto_assert(msg != NULL);
    crypto_assert(signature != NULL);

    size_t olen = 0;
    psa_call(psa_sign_message,
        ctx->key,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        msg,
        msg_len,
        signature,
        CRYPTO_DS_SIGNATURE_SIZE,
        &olen);
    crypto_assert(olen == CRYPTO_DS_SIGNATURE_SIZE);
}

err_t crypto_ds_verify(in const crypto_ds_context_t * ctx, in uint8_t * msg, in size_t msg_len,
    in uint8_t * signature)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->has_key);
    crypto_assert(msg != NULL);
    crypto_assert(signature != NULL);

    psa_status_t status;

    status = psa_verify_message(
        ctx->key,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        msg,
        msg_len,
        signature,
        CRYPTO_DS_SIGNATURE_SIZE);
    if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_SIGNATURE)
    {
        _psa_panic(status, __func__, __FILE__, __LINE__);
        return ERR_BAD_STATE;
    }
    return status == PSA_SUCCESS ? ERR_OK : ERR_VERIFICATION_FAILED;
}


void crypto_ds_import(in_out crypto_ds_context_t * ctx, in const uint8_t * pem, size_t pem_len)
{
    crypto_assert(ctx != NULL);
    crypto_assert(pem != NULL);

    if (ctx->has_key)
    {
        psa_call(psa_destroy_key, ctx->key);
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_call(mbedtls_pk_parse_key, &pk, (const uint8_t*)pem, pem_len,
        NULL, 0, mbedtls_ctr_drbg_random, &crypto_drbg);
    crypto_assert(mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY);
    crypto_assert(mbedtls_pk_get_bitlen(&pk) == 256);

    mbedtls_ecp_keypair * ecp = mbedtls_pk_ec(pk);

    uint8_t curve[CRYPTO_DS_KEY_SIZE];
    mbedtls_call(mbedtls_ecp_write_key,
        ecp,
        curve,
        CRYPTO_DS_KEY_SIZE);

    mbedtls_pk_free(&pk);
    mbedtls_ecp_keypair_free(ecp);

    psa_call(psa_import_key,
        &crypto_global.ds_default,
        curve,
        CRYPTO_DS_KEY_SIZE,
        &ctx->key);
    ctx->has_key = 1;
}

void crypto_ds_import_pubkey(in_out crypto_ds_context_t * ctx,
    in const uint8_t * pem, size_t pem_len)
{
    crypto_assert(ctx != NULL);
    crypto_assert(pem != NULL);

    if (ctx->has_key)
    {
        psa_call(psa_destroy_key, ctx->key);
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_call(mbedtls_pk_parse_public_key, &pk, (const uint8_t*)pem, pem_len);
    mbedtls_ecp_keypair * ecp = mbedtls_pk_ec(pk);
    crypto_assert(mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY);
    crypto_assert(mbedtls_pk_get_bitlen(&pk) == 256);

    /* curve is too large to put into the stack */
    uint8_t * curve = mbedtls_calloc(1, CRYPTO_DS_PUBKEY_SIZE);

    size_t olen;
    mbedtls_call(mbedtls_ecp_point_write_binary,
        &ecp->private_grp,
        &ecp->private_Q,
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &olen,
        curve,
        CRYPTO_DS_PUBKEY_SIZE);
    crypto_assert(olen == CRYPTO_DS_PUBKEY_SIZE);

    mbedtls_pk_free(&pk);
    mbedtls_ecp_keypair_free(ecp);

    psa_call(psa_import_key,
        &crypto_global.ds_pubkey_default,
        curve,
        CRYPTO_DS_PUBKEY_SIZE,
        &ctx->key);
    mbedtls_free(curve);

    ctx->has_key = 1;
}

void crypto_ds_export_pubkey(in const crypto_ds_context_t * ctx,
    out uint8_t * pubkey)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->has_key);
    crypto_assert(pubkey != NULL);

    size_t olen;
    psa_call(psa_export_public_key,
        ctx->key,
        pubkey,
        CRYPTO_DS_PUBKEY_SIZE,
        &olen);
    crypto_assert(olen == CRYPTO_DS_PUBKEY_SIZE);
}

/**
 * Public Key Infrastructure
 */
void crypto_pki_load_root(void)
{
    extern unsigned char device_key_pem[];
    extern size_t device_key_len;

    crypto_global.root.is_root = 1;
    crypto_global.root.parent = -1;

    crypto_ds_import(&crypto_global.root.ds, device_key_pem, device_key_len);
}

void crypto_pki_endorse(in const crypto_pki_context_t * endorser, in_out crypto_pki_context_t * endorsee)
{
    crypto_assert(endorser != NULL);
    crypto_assert(endorsee != NULL);

    if (!endorsee->ds.has_key)
    {
        psa_call(psa_generate_key, &crypto_global.ds_default, &endorsee->ds.key);
        endorsee->ds.has_key = 1;
    }
    uint8_t * pubkey = mbedtls_calloc(1, CRYPTO_DS_PUBKEY_SIZE);
    size_t olen;
    psa_call(psa_export_public_key, endorsee->ds.key, pubkey, CRYPTO_DS_PUBKEY_SIZE, &olen);
    crypto_assert(olen == CRYPTO_DS_PUBKEY_SIZE);
    crypto_ds_sign(&endorser->ds, pubkey, CRYPTO_DS_PUBKEY_SIZE, endorsee->endorsement);
    mbedtls_free(pubkey);
    endorsee->parent = endorser->ds.key;
    endorsee->is_root = 0;
}

const crypto_pki_context_t * crypto_pki_root(void)
{
    return &crypto_global.root;
}

err_t crypto_pki_verify(in uint8_t * pubkey, in uint8_t * identity, in uint8_t * endorsement)
{
    crypto_ds_context_t endorser = CRYPTO_DS_CONTEXT_INIT;
    psa_call(psa_import_key, &crypto_global.ds_pubkey_default, pubkey, CRYPTO_DS_PUBKEY_SIZE, &endorser.key);
    endorser.has_key = 1;
    err_t rv = crypto_ds_verify(&endorser, identity, CRYPTO_DS_PUBKEY_SIZE, endorsement);
    crypto_ds_free(&endorser);
    return rv;
}

void crypto_pki_free(in_out crypto_pki_context_t * ctx)
{
    crypto_assert(ctx != NULL);
    crypto_ds_free(&ctx->ds);
}

#if __cplusplus
};
#endif
