#ifdef _STD_LIBC_
#include <crypto/crypto.h>
#else
#include <lib/crypto/crypto.h>
#endif

/**
 * Crypto - mbedtls adaption interface
 */
#define CRYPTO_ERROR_MSG_LEN (512u)
_bss static char crypto_error_msg[CRYPTO_ERROR_MSG_LEN];

static inline void
_crypto_panic(
    int error_code, const char* func, const char* file, const int line)
{
    mbedtls_strerror(error_code, crypto_error_msg, CRYPTO_ERROR_MSG_LEN);
    crypto_error_msg[CRYPTO_ERROR_MSG_LEN - 1] = '\0';
    panic("fail to invoke the crypto library function (%s at %s:%d). error "
          "code %d (%s).\n",
        func, file, line, error_code, crypto_error_msg);
}

#define crypto_call(func, ...)                                                 \
    do                                                                         \
    {                                                                          \
        int _rv = func(__VA_ARGS__);                                           \
        if (_rv != 0)                                                          \
        {                                                                      \
            _crypto_panic(_rv, #func, __FILE__, __LINE__);                     \
        }                                                                      \
    } while (0)

/* TODO: make this to be TRUE RNG */
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
static int pseudo_entropy_source(void * data, unsigned char *output,
    size_t len, size_t *olen)
{
    size_t n = sizeof(crypto_entropy_source);
    size_t left = n - pseudo_entropy_counter;
    memcpy(output, crypto_entropy_source, left < len ? left : len);
    if (left < len)
    {
        memset(&output[left], 0xa4, n - left);
    }
    *olen = len;
    pseudo_entropy_counter = (pseudo_entropy_counter + len) % n;
    return 0;
}

static struct crypto_rng_context_t crypto_drbg;

_bss static unsigned char crypto_dynamic_memory[CRYPTO_DYNAMIC_MEMORY_SIZE]
    __attribute__((aligned(32)));

extern int mbedtls_entropy_add_source( mbedtls_entropy_context *ctx,
                        mbedtls_entropy_f_source_ptr f_source, void *p_source,
                        size_t threshold, int strong );

void
crypto_init(void)
{
    /* allocator */
    mbedtls_memory_buffer_alloc_init(
        crypto_dynamic_memory, CRYPTO_DYNAMIC_MEMORY_SIZE);

    /* drbg */
    mbedtls_ctr_drbg_init(&crypto_drbg.ctr_drbg);
    mbedtls_entropy_init(&crypto_drbg.entropy);
    mbedtls_entropy_add_source(&crypto_drbg.entropy, pseudo_entropy_source,
        NULL, 32, 1);

    crypto_call(mbedtls_ctr_drbg_seed, &crypto_drbg.ctr_drbg,
        mbedtls_entropy_func, &crypto_drbg.entropy,
        (const unsigned char*)crypto_entropy_source, CRYPTO_ENTROPY_LEN);
}

/**
 * Key Generation
 */
err_t
crypto_rng(out unsigned char* output, in size_t output_len)
{
    mbedtls_ctr_drbg_random(&crypto_drbg.ctr_drbg, output, output_len);
    return (ERR_OK);
}

/**
 * Base64
 */
err_t
crypto_b64_encode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen)
{
    crypto_call(mbedtls_base64_encode, dst, dlen, olen, src, slen);
    return (ERR_OK);
}

err_t
crypto_b64_decode(unsigned char* dst, size_t dlen, size_t* olen,
    const unsigned char* src, size_t slen)
{
    crypto_call(mbedtls_base64_decode, dst, dlen, olen, src, slen);
    return (ERR_OK);
}

/**
 * Secure Hash
 */
err_t
crypto_hash_init(in crypto_hash_context_t* ctx)
{
    mbedtls_sha256_init(ctx);
    crypto_call(mbedtls_sha256_starts, ctx, 0);
    return (ERR_OK);
}

err_t
crypto_hash_append(
    in crypto_hash_context_t* ctx, unsigned char* msg, size_t len)
{
    crypto_call(mbedtls_sha256_update, ctx, msg, len);
    return (ERR_OK);
}

/* the size of result should be larger than 32 */
err_t
crypto_hash_report(in crypto_hash_context_t* ctx, unsigned char* result)
{
    crypto_call(mbedtls_sha256_finish, ctx, result);
    mbedtls_sha256_free(ctx);
    return (ERR_OK);
}

/**
 * Digital Signature
 */
err_t
crypto_ds_init(in struct crypto_ds_context_t* ctx)
{
    mbedtls_ecdsa_init(&ctx->ecdsa_ctx);
    return (ERR_OK);
}

err_t
crypto_ds_gen_keypair(out struct crypto_ds_context_t* ctx)
{
    crypto_call(mbedtls_ecdsa_genkey, &ctx->ecdsa_ctx, ECDS_CURVE_SPEC,
        mbedtls_ctr_drbg_random, &crypto_drbg.ctr_drbg);

    return (ERR_OK);
}

err_t
crypto_ds_import_pem_keypair(in unsigned char* pem, in size_t pem_len,
    in unsigned char* passwd, in size_t passwd_len,
    out struct crypto_ds_context_t* key_ctx)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    crypto_call(mbedtls_pk_parse_key, &pk, pem, pem_len, passwd, passwd_len,
        mbedtls_ctr_drbg_random, &crypto_drbg.ctr_drbg);
    crypto_assert(mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY);
    mbedtls_ecp_keypair * ecp = mbedtls_pk_ec(pk);

    mbedtls_ecdsa_init(&key_ctx->ecdsa_ctx);
    crypto_call(mbedtls_ecp_group_copy, &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp), &ecp->MBEDTLS_PRIVATE(grp));
    crypto_call(mbedtls_ecp_copy, &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(Q), &ecp->MBEDTLS_PRIVATE(Q));
    crypto_call(mbedtls_mpi_copy, &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(d), &ecp->MBEDTLS_PRIVATE(d));

    mbedtls_pk_free(&pk);

    return (ERR_OK);
}

err_t
crypto_ds_import_pem_public_key(in unsigned char* pem, in size_t pem_len,
    out struct crypto_ds_context_t* key_ctx)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    crypto_call(mbedtls_pk_parse_public_key, &pk, pem, pem_len);
    crypto_assert(mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY);

    mbedtls_ecp_keypair * ecp = mbedtls_pk_ec(pk);
    mbedtls_ecdsa_init(&key_ctx->ecdsa_ctx);
    crypto_call(mbedtls_ecp_group_copy, &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp), &ecp->MBEDTLS_PRIVATE(grp));
    crypto_call(mbedtls_ecp_copy, &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(Q), &ecp->MBEDTLS_PRIVATE(Q));

    mbedtls_pk_free(&pk);
    return (ERR_OK);
}

err_t
crypto_ds_export_pem_public_key(in struct crypto_ds_context_t* key_ctx,
    out unsigned char* pem, out size_t pem_len)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    const mbedtls_pk_info_t* pk_info
        = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    crypto_call(mbedtls_pk_setup, &pk, pk_info);
    mbedtls_ecp_keypair * ecp = mbedtls_pk_ec(pk);
    crypto_call(mbedtls_ecp_group_copy, &ecp->MBEDTLS_PRIVATE(grp), &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp));
    crypto_call(mbedtls_ecp_copy, &ecp->MBEDTLS_PRIVATE(Q), &key_ctx->ecdsa_ctx.MBEDTLS_PRIVATE(Q));

    crypto_call(mbedtls_pk_write_pubkey_pem, &pk, pem, pem_len);

    return (ERR_OK);
}

err_t
crypto_ds_export_public_key(
    in struct crypto_ds_context_t* ctx, out struct crypto_ds_public_key_t* pk)
{
    crypto_call(mbedtls_ecp_point_write_binary,
        &ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp),
        &ctx->ecdsa_ctx.MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &pk->len, pk->key, sizeof(pk->key));
    crypto_assert(pk->len < ECDS_PK_SIZE);

    return (ERR_OK);
}

err_t
crypto_ds_import_public_key(
    out struct crypto_ds_context_t* ctx, in struct crypto_ds_public_key_t* pk)
{
    /* load curve structure */
    crypto_call(mbedtls_ecp_group_load, &ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp), ECDS_CURVE_SPEC);
    /* load key */
    crypto_call(mbedtls_ecp_point_read_binary,
        &ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp),
        &ctx->ecdsa_ctx.MBEDTLS_PRIVATE(Q),
        pk->key, pk->len);

    return (ERR_OK);
}

err_t
crypto_ds_export_private_key(
    in struct crypto_ds_context_t* ctx, out struct crypto_ds_private_key_t* sk)
{
    sk->len = (ctx->ecdsa_ctx.MBEDTLS_PRIVATE(grp).pbits + 7) / 8;
    crypto_call(mbedtls_ecp_write_key, &ctx->ecdsa_ctx, sk->key, sk->len);
    crypto_assert(sk->len < ECDS_SK_SIZE);

    return (ERR_OK);
}

err_t
crypto_ds_import_private_key(
    out struct crypto_ds_context_t* ctx, in struct crypto_ds_private_key_t* sk)
{
    crypto_call(mbedtls_ecp_read_key, ECDS_CURVE_SPEC, &ctx->ecdsa_ctx, sk->key,
        sk->len);

    return (ERR_OK);
}

void
crypto_ds_free(in struct crypto_ds_context_t* ctx)
{
    mbedtls_ecdsa_free(&ctx->ecdsa_ctx);
}

err_t
crypto_sign_hashed(in struct crypto_ds_context_t* ctx, in unsigned char* sha256,
    out struct crypto_ds_signature_t* sig)
{
    crypto_call(mbedtls_ecdsa_write_signature, &ctx->ecdsa_ctx,
        MBEDTLS_MD_SHA256, sha256, 32, sig->signature,
        MBEDTLS_ECDSA_MAX_LEN, &sig->len,
        mbedtls_ctr_drbg_random, &crypto_drbg.ctr_drbg);

    return (ERR_OK);
}

err_t
crypto_sign(in struct crypto_ds_context_t* ctx, in message_t msg, in size_t len,
    out struct crypto_ds_signature_t* sig)
{
    crypto_assert(sig != NULL);

    /* measure the hash of the message */
    mbedtls_sha256_init(&ctx->sha256_ctx);

    crypto_call(mbedtls_sha256_starts, &ctx->sha256_ctx, 0);
    crypto_call(mbedtls_sha256_update, &ctx->sha256_ctx, msg, len);
    crypto_call(mbedtls_sha256_finish, &ctx->sha256_ctx, ctx->sha256_hash);
    mbedtls_sha256_free(&ctx->sha256_ctx);

    /* sign the hash with sk */
    crypto_sign_hashed(ctx, ctx->sha256_hash, sig);

    return (ERR_OK);
}

err_t
crypto_verify_hashed(in struct crypto_ds_context_t* ctx,
    in unsigned char* sha256, in struct crypto_ds_signature_t* sig,
    out int* match)
{
    int rv;

    rv = mbedtls_ecdsa_read_signature(
        &ctx->ecdsa_ctx, sha256, 32, sig->signature, sig->len);
    *match = (rv == 0 ? 1 : 0);

    return (rv);
}

err_t
crypto_verify(in struct crypto_ds_context_t* ctx, in message_t msg,
    in size_t len, in struct crypto_ds_signature_t* sig, out int* match)
{
    int rv;

    /* measure the hash of the message */
    mbedtls_sha256_init(&ctx->sha256_ctx);

    crypto_call(mbedtls_sha256_starts, &ctx->sha256_ctx, 0);
    crypto_call(mbedtls_sha256_update, &ctx->sha256_ctx, msg, len);
    crypto_call(mbedtls_sha256_finish, &ctx->sha256_ctx, ctx->sha256_hash);
    mbedtls_sha256_free(&ctx->sha256_ctx);

    rv = crypto_verify_hashed(ctx, ctx->sha256_hash, sig, match);
    return (rv);
}

/**
 * PKI
 */
err_t
crypto_pki_new(in struct crypto_pki_context_t* ctx,
    in struct crypto_ds_context_t*             authority)
{
    ctx->authority = authority;
    crypto_ds_gen_keypair(&ctx->client);
    crypto_ds_export_public_key(&ctx->client, &ctx->cert.pk);

    crypto_sign(authority, ctx->cert.pk.key, ctx->cert.pk.len, &ctx->cert.sig);
    return (ERR_OK);
}

int
crypto_pki_verify(in struct crypto_pki_context_t* ctx)
{
    crypto_assert(ctx->authority != NULL);
    crypto_ds_export_public_key(&ctx->client, &ctx->cert.pk);

    int succ;
    crypto_verify(ctx->authority, ctx->cert.pk.key, ctx->cert.pk.len,
        &ctx->cert.sig, &succ);

    return succ;
}

err_t
crypto_pki_load_signature(
    in struct crypto_pki_context_t* ctx, in char* sig_b64, in size_t sig_len)
{
    crypto_call(crypto_b64_decode, ctx->cert.sig.signature,
        MBEDTLS_ECDSA_MAX_LEN, &ctx->cert.sig.len,
        (const unsigned char*)sig_b64, sig_len);

    return (ERR_OK);
}

/**
 * Key Exchange
 */
err_t
crypto_dh_genkey(
    in struct crypto_dh_context_t* ctx, out struct crypto_dh_curve_t* curve)
{
    mbedtls_ecdh_init(&ctx->ecdh_ctx);
    crypto_call(mbedtls_ecdh_setup, &ctx->ecdh_ctx, MBEDTLS_ECP_DP_CURVE25519);

    crypto_call(mbedtls_ecdh_make_params, &ctx->ecdh_ctx, &curve->len,
        curve->curve, CRYPTO_DH_CURVE_SIZE, mbedtls_ctr_drbg_random,
        &crypto_drbg.ctr_drbg);

    return (ERR_OK);
}

err_t
crypto_dh_exchange_genkey(in struct crypto_dh_context_t* ctx,
    in struct crypto_dh_curve_t* curve, out struct crypto_dh_key_t* shared,
    out struct crypto_dh_key_t* secrete)
{

    mbedtls_ecdh_init(&ctx->ecdh_ctx);

    const unsigned char* crv = curve->curve;
    crypto_call(mbedtls_ecdh_read_params, &ctx->ecdh_ctx, &crv,
        curve->curve + curve->len);

    /* generate the public key to exchange */
    crypto_call(mbedtls_ecdh_make_public, &ctx->ecdh_ctx, &shared->len,
        shared->key, CRYPTO_DH_KEY_SIZE, mbedtls_ctr_drbg_random,
        &crypto_drbg.ctr_drbg);

    /* calculate the secrete key */
    crypto_call(mbedtls_ecdh_calc_secret, &ctx->ecdh_ctx, &secrete->len,
        secrete->key, CRYPTO_DH_KEY_SIZE, mbedtls_ctr_drbg_random,
        &crypto_drbg.ctr_drbg);

    mbedtls_ecdh_free(&ctx->ecdh_ctx);

    return (ERR_OK);
}

err_t
crypto_dh_exchange(in struct crypto_dh_context_t* ctx,
    in struct crypto_dh_key_t* shared, out struct crypto_dh_key_t* secrete)
{
    /* read public key */
    crypto_call(
        mbedtls_ecdh_read_public, &ctx->ecdh_ctx, shared->key, shared->len);

    /* exchange */
    crypto_call(mbedtls_ecdh_calc_secret, &ctx->ecdh_ctx, &secrete->len,
        secrete->key, CRYPTO_DH_KEY_SIZE, mbedtls_ctr_drbg_random,
        &crypto_drbg.ctr_drbg);

    mbedtls_ecdh_free(&ctx->ecdh_ctx);

    return (ERR_OK);
}

/**
 * Stream Cipher
 */
err_t
crypto_sc_init(struct crypto_sc_context_t* ctx, sk_t sk, size_t sk_len)
{
    mbedtls_chacha20_init(&ctx->chacha20);

    /* create a 32 Bytes key */
    mbedtls_sha256_init(&ctx->sha256_ctx);
    crypto_call(mbedtls_sha256_starts, &ctx->sha256_ctx, 0);
    crypto_call(mbedtls_sha256_update, &ctx->sha256_ctx, sk, sk_len);
    crypto_call(mbedtls_sha256_finish, &ctx->sha256_ctx, ctx->sha256_hash);

    /* setup stream cipher */
    crypto_call(mbedtls_chacha20_setkey, &ctx->chacha20, ctx->sha256_hash);

    /* and a 12 Bytes nonce */
    crypto_call(mbedtls_sha256_starts, &ctx->sha256_ctx, 0);
    crypto_call(
        mbedtls_sha256_update, &ctx->sha256_ctx, ctx->sha256_hash, 32);
    crypto_call(mbedtls_sha256_finish, &ctx->sha256_ctx, ctx->sha256_hash);

    /* setup stream cipher */
    crypto_call(mbedtls_chacha20_starts, &ctx->chacha20, ctx->sha256_hash, 0);

    mbedtls_sha256_free(&ctx->sha256_ctx);
    return (ERR_OK);
}

err_t
crypto_sc_encrypt(in struct crypto_sc_context_t* ctx, in message_t msg,
    in size_t msg_len, out cyphertext_t ciphertext)
{
    crypto_call(
        mbedtls_chacha20_update, &ctx->chacha20, msg_len, msg, ciphertext);
    return (ERR_OK);
}

err_t
crypto_sc_decrypt(in struct crypto_sc_context_t* ctx,
    in cyphertext_t ciphertext, in size_t ciphertext_len, out message_t msg)
{
    /* xor: encrypt the message again = decrypt */
    crypto_sc_encrypt(ctx, ciphertext, ciphertext_len, msg);
    return (ERR_OK);
}

/**
 * Stream Cipher - with MAC
 */
_bss static unsigned char crypto_sc_mac_starter[32];

err_t
crypto_sc_mac_init(in struct crypto_sc_mac_context_t* ctx, in sk_t sk,
    in size_t sk_len, in int to_encrypt)
{
    mbedtls_chachapoly_init(&ctx->chachapoly);
    memset(crypto_sc_mac_starter, 0, sizeof(crypto_sc_mac_starter));

    /* create a 32 Bytes key */
    mbedtls_sha256_init(&ctx->sha256_ctx);
    crypto_call(mbedtls_sha256_starts, &ctx->sha256_ctx, 0);
    crypto_call(mbedtls_sha256_update, &ctx->sha256_ctx, sk, sk_len);
    crypto_call(mbedtls_sha256_finish, &ctx->sha256_ctx, ctx->sha256_hash);

    /* setup stream cipher */
    crypto_call(mbedtls_chachapoly_setkey, &ctx->chachapoly, ctx->sha256_hash);

    /* and a 12 Bytes nonce */
    crypto_call(mbedtls_sha256_starts, &ctx->sha256_ctx, 0);
    crypto_call(
        mbedtls_sha256_update, &ctx->sha256_ctx, ctx->sha256_hash, 32);
    crypto_call(mbedtls_sha256_finish, &ctx->sha256_ctx, ctx->sha256_hash);

    /* setup stream cipher */
    crypto_call(mbedtls_chachapoly_starts, &ctx->chachapoly, ctx->sha256_hash,
        to_encrypt ? MBEDTLS_CHACHAPOLY_ENCRYPT : MBEDTLS_CHACHAPOLY_DECRYPT);

    mbedtls_sha256_free(&ctx->sha256_ctx);
    return (ERR_OK);
}

err_t
crypto_sc_mac_encrypt(in struct crypto_sc_mac_context_t* ctx, in message_t msg,
    in size_t msg_len, out cyphertext_t cipher_tag, out size_t* cipher_tag_len)
{
    crypto_call(
        mbedtls_chachapoly_update, &ctx->chachapoly, msg_len, msg, cipher_tag);
    crypto_call(
        mbedtls_chachapoly_finish, &ctx->chachapoly, cipher_tag + msg_len);

    /* update nonce, and restart */
    crypto_call(mbedtls_chacha20_update, &ctx->chachapoly.MBEDTLS_PRIVATE(chacha20_ctx),
        12u,
        crypto_sc_mac_starter, ctx->sha256_hash);
    crypto_call(mbedtls_chachapoly_starts, &ctx->chachapoly, ctx->sha256_hash,
        MBEDTLS_CHACHAPOLY_ENCRYPT);

    /* append 16 B tag */
    *cipher_tag_len = msg_len + 16u;
    return (ERR_OK);
}

int
crypto_sc_mac_decrypt(in struct crypto_sc_mac_context_t* ctx,
    in cyphertext_t cipher_tag, in size_t cipher_tag_len, out message_t msg,
    out size_t* msg_len)
{
    if (cipher_tag_len <= 16)
    {
        return (FALSE);
    }

    crypto_call(mbedtls_chachapoly_update, &ctx->chachapoly,
        cipher_tag_len - 16, cipher_tag, msg);
    crypto_call(mbedtls_chachapoly_finish, &ctx->chachapoly, ctx->poly1305_tag);

    /* update nonce, and restart */
    crypto_call(mbedtls_chacha20_update, &ctx->chachapoly.MBEDTLS_PRIVATE(chacha20_ctx), 12u,
        crypto_sc_mac_starter, ctx->sha256_hash);
    crypto_call(mbedtls_chachapoly_starts, &ctx->chachapoly, ctx->sha256_hash,
        MBEDTLS_CHACHAPOLY_DECRYPT);

    int diff
        = memcmp(&cipher_tag[cipher_tag_len - 16u], ctx->poly1305_tag, 16u);
    *msg_len = cipher_tag_len - 16u;
    return (diff ? FALSE : TRUE);
}
