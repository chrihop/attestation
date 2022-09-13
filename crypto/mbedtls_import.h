#ifndef _LIB_CRYPTO_MBEDTLS_IMPORT_H_
#define _LIB_CRYPTO_MBEDTLS_IMPORT_H_

#include "crypto_context.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*******************************************************************************
     * mbedtls declarations (v2.26.0) - linked with libmbedcrypto.a
     ******************************************************************************/
    void mbedtls_strerror(int errnum, char* buffer, size_t buflen);

    /**
     * static memory allocator
     */
    void mbedtls_memory_buffer_alloc_init(unsigned char* buf, size_t len);

    void mbedtls_memory_buffer_alloc_status(void);

/**
 * Big Number
 */
#if defined(__LP64__)
    typedef int64_t  mbedtls_mpi_sint;
    typedef uint64_t mbedtls_mpi_uint;
#else
typedef int32_t  mbedtls_mpi_sint;
typedef uint32_t mbedtls_mpi_uint;
#endif

    typedef struct mbedtls_mpi
    {
        int    s; /*!<  Sign: -1 if the mpi is negative, 1 otherwise */
        size_t n; /*!<  total # of limbs  */
        mbedtls_mpi_uint* p; /*!<  pointer to limbs  */
    } mbedtls_mpi;

    int mbedtls_mpi_lset(mbedtls_mpi* X, mbedtls_mpi_sint z);

    int mbedtls_mpi_write_binary(
        const mbedtls_mpi* X, unsigned char* buf, size_t buflen);

    int mbedtls_mpi_read_binary(
        mbedtls_mpi* X, const unsigned char* buf, size_t buflen);

    int mbedtls_mpi_copy(mbedtls_mpi* X, const mbedtls_mpi* Y);

    int mbedtls_mpi_write_string(const mbedtls_mpi* X, int radix, char* buf,
        size_t buflen, size_t* olen);

    /**
     * BASE64
     */
    int mbedtls_base64_encode(unsigned char* dst, size_t dlen, size_t* olen,
        const unsigned char* src, size_t slen);

    int mbedtls_base64_decode(unsigned char* dst, size_t dlen, size_t* olen,
        const unsigned char* src, size_t slen);

    /**
     * SHA
     */
    typedef struct mbedtls_sha256_context
    {
        uint32_t      total[2];   /*!< The number of Bytes processed.  */
        uint32_t      state[8];   /*!< The intermediate digest state.  */
        unsigned char buffer[64]; /*!< The data block being processed. */
        int           is224;      /*!< Determines which function to use:
                                         0: Use SHA-256, or 1: Use SHA-224. */
    } mbedtls_sha256_context;

    void mbedtls_sha256_init(mbedtls_sha256_context* ctx);
    void mbedtls_sha256_free(mbedtls_sha256_context* ctx);
    int  mbedtls_sha256_starts(mbedtls_sha256_context* ctx, int is224);
    int  mbedtls_sha256_update(
         mbedtls_sha256_context* ctx, const unsigned char* input, size_t ilen);
    int mbedtls_sha256_finish(
        mbedtls_sha256_context* ctx, unsigned char output[32]);

    typedef struct mbedtls_sha512_context
    {
        uint64_t      total[2];    /*!< The number of Bytes processed. */
        uint64_t      state[8];    /*!< The intermediate digest state. */
        unsigned char buffer[128]; /*!< The data block being processed. */
        int           is384;       /*!< Determines which function to use:
                                         0: Use SHA-512, or 1: Use SHA-384. */
    } mbedtls_sha512_context;

    void mbedtls_sha512_init(mbedtls_sha512_context* ctx);
    void mbedtls_sha512_free(mbedtls_sha512_context* ctx);
    int  mbedtls_sha512_starts_ret(mbedtls_sha512_context* ctx, int is384);
    int  mbedtls_sha512_update_ret(
         mbedtls_sha512_context* ctx, const unsigned char* input, size_t ilen);
    int mbedtls_sha512_finish_ret(
        mbedtls_sha512_context* ctx, unsigned char output[64]);

    typedef enum
    {
        MBEDTLS_PK_NONE = 0,
        MBEDTLS_PK_RSA,
        MBEDTLS_PK_ECKEY,
        MBEDTLS_PK_ECKEY_DH,
        MBEDTLS_PK_ECDSA,
        MBEDTLS_PK_RSA_ALT,
        MBEDTLS_PK_RSASSA_PSS,
        MBEDTLS_PK_OPAQUE,
    } mbedtls_pk_type_t;

    typedef enum
    {
        MBEDTLS_ECP_DP_NONE = 0,   /*!< Curve not defined. */
        MBEDTLS_ECP_DP_SECP192R1,  /*!< Domain parameters for the 192-bit curve
                                      defined by FIPS 186-4 and SEC1. */
        MBEDTLS_ECP_DP_SECP224R1,  /*!< Domain parameters for the 224-bit curve
                                      defined by FIPS 186-4 and SEC1. */
        MBEDTLS_ECP_DP_SECP256R1,  /*!< Domain parameters for the 256-bit curve
                                      defined by FIPS 186-4 and SEC1. */
        MBEDTLS_ECP_DP_SECP384R1,  /*!< Domain parameters for the 384-bit curve
                                      defined by FIPS 186-4 and SEC1. */
        MBEDTLS_ECP_DP_SECP521R1,  /*!< Domain parameters for the 521-bit curve
                                      defined by FIPS 186-4 and SEC1. */
        MBEDTLS_ECP_DP_BP256R1,    /*!< Domain parameters for 256-bit Brainpool
                                      curve. */
        MBEDTLS_ECP_DP_BP384R1,    /*!< Domain parameters for 384-bit Brainpool
                                      curve. */
        MBEDTLS_ECP_DP_BP512R1,    /*!< Domain parameters for 512-bit Brainpool
                                      curve. */
        MBEDTLS_ECP_DP_CURVE25519, /*!< Domain parameters for Curve25519. */
        MBEDTLS_ECP_DP_SECP192K1,  /*!< Domain parameters for 192-bit "Koblitz"
                                      curve. */
        MBEDTLS_ECP_DP_SECP224K1,  /*!< Domain parameters for 224-bit "Koblitz"
                                      curve. */
        MBEDTLS_ECP_DP_SECP256K1,  /*!< Domain parameters for 256-bit "Koblitz"
                                      curve. */
        MBEDTLS_ECP_DP_CURVE448,   /*!< Domain parameters for Curve448. */
    } mbedtls_ecp_group_id;

    typedef struct mbedtls_ecp_point
    {
        mbedtls_mpi X; /*!< The X coordinate of the ECP point. */
        mbedtls_mpi Y; /*!< The Y coordinate of the ECP point. */
        mbedtls_mpi Z; /*!< The Z coordinate of the ECP point. */
    } mbedtls_ecp_point;

    typedef struct mbedtls_ecp_group
    {
        mbedtls_ecp_group_id id; /*!< An internal group identifier. */
        mbedtls_mpi          P;  /*!< The prime modulus of the base field. */
        mbedtls_mpi A; /*!< For Short Weierstrass: \p A in the equation. For
            Montgomery curves: <code>(A + 2) / 4</code>. */
        mbedtls_mpi B; /*!< For Short Weierstrass: \p B in the equation.
            For Montgomery curves: unused. */
        mbedtls_ecp_point G;     /*!< The generator of the subgroup used. */
        mbedtls_mpi       N;     /*!< The order of \p G. */
        size_t            pbits; /*!< The number of bits in \p P.*/
        size_t nbits;   /*!< For Short Weierstrass: The number of bits in \p P.
             For Montgomery curves: the number of bits in the
             private keys. */
        unsigned int h; /*!< \internal 1 if the constants are static. */
        int (*modp)(mbedtls_mpi*); /*!< The function for fast pseudo-reduction
                        mod \p P (see above).*/
        int (*t_pre)(mbedtls_ecp_point*, void*);  /*!< Unused. */
        int (*t_post)(mbedtls_ecp_point*, void*); /*!< Unused. */
        void*              t_data;                /*!< Unused. */
        mbedtls_ecp_point* T; /*!< Pre-computed points for ecp_mul_comb(). */
        size_t             T_size; /*!< The number of pre-computed points. */
    } mbedtls_ecp_group;

    typedef struct mbedtls_ecp_keypair
    {
        mbedtls_ecp_group grp; /*!<  Elliptic curve and base point     */
        mbedtls_mpi       d;   /*!<  our secret value                  */
        mbedtls_ecp_point Q;   /*!<  our public value                  */
    } mbedtls_ecp_keypair;

    typedef mbedtls_ecp_keypair mbedtls_ecdsa_context;

    typedef enum
    {
        MBEDTLS_MD_NONE = 0,  /**< None. */
        MBEDTLS_MD_MD2,       /**< The MD2 message digest. */
        MBEDTLS_MD_MD4,       /**< The MD4 message digest. */
        MBEDTLS_MD_MD5,       /**< The MD5 message digest. */
        MBEDTLS_MD_SHA1,      /**< The SHA-1 message digest. */
        MBEDTLS_MD_SHA224,    /**< The SHA-224 message digest. */
        MBEDTLS_MD_SHA256,    /**< The SHA-256 message digest. */
        MBEDTLS_MD_SHA384,    /**< The SHA-384 message digest. */
        MBEDTLS_MD_SHA512,    /**< The SHA-512 message digest. */
        MBEDTLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
    } mbedtls_md_type_t;

#define MBEDTLS_ECP_MAX_BITS 521 /**< The maximum size of groups, in bits. */

#define MBEDTLS_ECDSA_MAX_SIG_LEN(bits)                                        \
    (/*T,L of SEQUENCE*/ ((bits) >= 61 * 8 ? 3 : 2) + /*T,L of r,s*/ 2         \
            * (((bits) >= 127 * 8 ? 3 : 2) + /*V of r,s*/ ((bits) + 8) / 8))

/** The maximal size of an ECDSA signature in Bytes. */
#define MBEDTLS_ECDSA_MAX_LEN MBEDTLS_ECDSA_MAX_SIG_LEN(MBEDTLS_ECP_MAX_BITS)

    void mbedtls_ecdsa_init(mbedtls_ecdsa_context* ctx);

    void mbedtls_ecdsa_free(mbedtls_ecdsa_context* ctx);

    int  mbedtls_ecp_copy(mbedtls_ecp_point* P, const mbedtls_ecp_point* Q);

    int  mbedtls_ecp_group_copy(
         mbedtls_ecp_group* dst, const mbedtls_ecp_group* src);

    int mbedtls_ecp_group_load(mbedtls_ecp_group* grp, mbedtls_ecp_group_id id);

    int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context* ctx,
        mbedtls_ecp_group_id gid, int (*f_rng)(void*, unsigned char*, size_t),
        void*                p_rng);

    int mbedtls_ecp_write_key(
        mbedtls_ecp_keypair* key, unsigned char* buf, size_t buflen);

    int mbedtls_ecp_read_key(mbedtls_ecp_group_id grp_id,
        mbedtls_ecp_keypair* key, const unsigned char* buf, size_t buflen);

#define MBEDTLS_ECP_PF_UNCOMPRESSED 0 /**< Uncompressed point format. */
#define MBEDTLS_ECP_PF_COMPRESSED   1 /**< Compressed point format. */

    int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group* grp,
        const mbedtls_ecp_point* P, int format, size_t* olen,
        unsigned char* buf, size_t buflen);

    int mbedtls_ecp_point_read_binary(const mbedtls_ecp_group* grp,
        mbedtls_ecp_point* P, const unsigned char* buf, size_t ilen);

    int mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context* ctx,
        mbedtls_md_type_t md_alg, const unsigned char* hash, size_t hlen,
        unsigned char* sig, size_t*                        slen,
        int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    int mbedtls_ecdsa_read_signature(mbedtls_ecdsa_context* ctx,
        const unsigned char* hash, size_t hlen, const unsigned char* sig,
        size_t slen);

    typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;

    typedef struct mbedtls_pk_context
    {
        const mbedtls_pk_info_t* pk_info; /**< Public key information         */
        void*                    pk_ctx;  /**< Underlying public key context  */
    } mbedtls_pk_context;

    int mbedtls_pk_parse_key(mbedtls_pk_context* ctx, const unsigned char* key,
        size_t keylen, const unsigned char* pwd, size_t pwdlen);

    int mbedtls_pk_write_pubkey_pem(
        mbedtls_pk_context* ctx, unsigned char* buf, size_t size);

    int mbedtls_pk_parse_public_key(
        mbedtls_pk_context* ctx, const unsigned char* key, size_t keylen);

    mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context* ctx);

    int               mbedtls_pk_setup(
                      mbedtls_pk_context* ctx, const mbedtls_pk_info_t* info);

    const mbedtls_pk_info_t* mbedtls_pk_info_from_type(
        mbedtls_pk_type_t pk_type);

    void mbedtls_pk_init(mbedtls_pk_context* ctx);

    void mbedtls_pk_free(mbedtls_pk_context* ctx);

    /**
     * ECDH
     */
    typedef enum
    {
        MBEDTLS_ECDH_VARIANT_NONE = 0,    /*!< Implementation not defined. */
        MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0, /*!< The default Mbed TLS
                                             implementation */
    } mbedtls_ecdh_variant;

    typedef struct mbedtls_ecdh_context_mbed
    {
        mbedtls_ecp_group grp; /*!< The elliptic curve used. */
        mbedtls_mpi       d;   /*!< The private key. */
        mbedtls_ecp_point Q;   /*!< The public key. */
        mbedtls_ecp_point Qp;  /*!< The value of the public key of the peer. */
        mbedtls_mpi       z;   /*!< The shared secret. */
    } mbedtls_ecdh_context_mbed;

    typedef struct mbedtls_ecdh_context
    {
        uint8_t point_format; /*!< The format of point export in TLS messages
                               as defined in RFC 4492. */
        mbedtls_ecp_group_id grp_id; /*!< The elliptic curve used. */
        mbedtls_ecdh_variant
            var; /*!< The ECDH implementation/structure used. */
        union
        {
            mbedtls_ecdh_context_mbed mbed_ecdh;
        } ctx; /*!< Implementation-specific context. The
                    context in use is specified by the \c var
                    field. */
    } mbedtls_ecdh_context;

    void mbedtls_ecdh_init(mbedtls_ecdh_context* ctx);

    void mbedtls_ecdh_free(mbedtls_ecdh_context* ctx);

    /* select curve */
    int  mbedtls_ecdh_setup(
         mbedtls_ecdh_context* ctx, mbedtls_ecp_group_id grp_id);

    int mbedtls_ecdh_make_params(mbedtls_ecdh_context* ctx, size_t* olen,
        unsigned char* buf, size_t                         blen,
        int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    int mbedtls_ecdh_read_params(mbedtls_ecdh_context* ctx,
        const unsigned char** buf, const unsigned char* end);

    int mbedtls_ecdh_make_public(mbedtls_ecdh_context* ctx, size_t* olen,
        unsigned char* buf, size_t                         blen,
        int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    int mbedtls_ecdh_read_public(
        mbedtls_ecdh_context* ctx, const unsigned char* buf, size_t blen);

    int mbedtls_ecdh_calc_secret(mbedtls_ecdh_context* ctx, size_t* olen,
        unsigned char* buf, size_t                         blen,
        int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    /**
     * RNG
     */
    typedef int (*mbedtls_entropy_f_source_ptr)(
        void* data, unsigned char* output, size_t len, size_t* olen);

    typedef struct mbedtls_entropy_source_state
    {
        mbedtls_entropy_f_source_ptr
               f_source;  /**< The entropy source callback */
        void*  p_source;  /**< The callback data pointer */
        size_t size;      /**< Amount received in bytes */
        size_t threshold; /**< Minimum bytes required before release */
        int    strong;    /**< Is the source strong? */
    } mbedtls_entropy_source_state;

#define MBEDTLS_ENTROPY_MAX_SOURCES                                            \
    20 /**< Maximum number of sources supported */

    typedef struct mbedtls_entropy_context
    {
        int                    accumulator_started; /* 0 after init.
                                                     * 1 after the first update.
                                                     * -1 after free. */
        mbedtls_sha256_context accumulator;
        int source_count; /* Number of entries used in source. */
        mbedtls_entropy_source_state source[MBEDTLS_ENTROPY_MAX_SOURCES];
    } mbedtls_entropy_context;

    typedef struct mbedtls_aes_context
    {
        int       nr;      /*!< The number of rounds. */
        uint32_t* rk;      /*!< AES round keys. */
        uint32_t  buf[68]; /*!< Unaligned data buffer. This buffer can
                              hold 32 extra Bytes, which can be used for
                              one of the following purposes:
                              <ul><li>Alignment if VIA padlock is
                                      used.</li>
                              <li>Simplifying key expansion in the 256-bit
                                  case by generating an extra round key.
                                  </li></ul> */
    } mbedtls_aes_context;

    typedef struct mbedtls_ctr_drbg_context
    {
        unsigned char counter[16];    /*!< The counter (V). */
        int           reseed_counter; /*!< The reseed counter.
                                       * This is the number of requests that have
                                       * been made since the last (re)seeding,
                                       * minus one.
                                       * Before the initial seeding, this field
                                       * contains the amount of entropy in bytes
                                       * to use as a nonce for the initial seeding,
                                       * or -1 if no nonce length has been explicitly
                                       * set (see mbedtls_ctr_drbg_set_nonce_len()).
                                       */
        int    prediction_resistance; /*!< This determines whether prediction
                                            resistance is enabled, that is
                                            whether to systematically reseed before
                                            each random generation. */
        size_t entropy_len;           /*!< The amount of entropy grabbed on each
                                            seed or reseed operation, in bytes. */
        int    reseed_interval;       /*!< The reseed interval.
                                       * This is the maximum number of requests
                                       * that can be made between reseedings. */

        mbedtls_aes_context aes_ctx; /*!< The AES context. */

        /*
         * Callbacks (Entropy)
         */
        int (*f_entropy)(void*, unsigned char*, size_t);
        /*!< The entropy callback function. */

        void* p_entropy; /*!< The context for the entropy function. */

    } mbedtls_ctr_drbg_context;

    void mbedtls_entropy_init(mbedtls_entropy_context* ctx);

    void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context* ctx);

    int  mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context* ctx,
         int (*f_entropy)(void*, unsigned char*, size_t), void* p_entropy,
         const unsigned char* custom, size_t len);

    int  mbedtls_ctr_drbg_random(
         void* p_rng, unsigned char* output, size_t output_len);

    int mbedtls_entropy_func(void* data, unsigned char* output, size_t len);

    /**
     * Chacha20
     */
    typedef struct mbedtls_chacha20_context
    {
        uint32_t state[16];      /*! The state (before round operations). */
        uint8_t  keystream8[64]; /*! Leftover keystream bytes. */
        size_t
            keystream_bytes_used; /*! Number of keystream bytes already used. */
    } mbedtls_chacha20_context;

    void mbedtls_chacha20_init(mbedtls_chacha20_context* ctx);

    void mbedtls_chacha20_free(mbedtls_chacha20_context* ctx);

    int  mbedtls_chacha20_setkey(
         mbedtls_chacha20_context* ctx, const unsigned char key[32]);

    int mbedtls_chacha20_starts(mbedtls_chacha20_context* ctx,
        const unsigned char nonce[12], uint32_t counter);

    int mbedtls_chacha20_update(mbedtls_chacha20_context* ctx, size_t size,
        const unsigned char* input, unsigned char* output);

    /**
     * Poly1305
     */
    typedef struct mbedtls_poly1305_context
    {
        uint32_t r[4];      /** The value for 'r' (low 128 bits of the key). */
        uint32_t s[4];      /** The value for 's' (high 128 bits of the key). */
        uint32_t acc[5];    /** The accumulator number. */
        uint8_t  queue[16]; /** The current partial block of data. */
        size_t   queue_len; /** The number of bytes stored in 'queue'. */
    } mbedtls_poly1305_context;

    void mbedtls_poly1305_init(mbedtls_poly1305_context* ctx);

    void mbedtls_poly1305_free(mbedtls_poly1305_context* ctx);

    int  mbedtls_poly1305_starts(
         mbedtls_poly1305_context* ctx, const unsigned char key[32]);

    int mbedtls_poly1305_update(
        mbedtls_poly1305_context* ctx, const unsigned char* input, size_t ilen);

    int mbedtls_poly1305_finish(
        mbedtls_poly1305_context* ctx, unsigned char mac[16]);

    /**
     * Chacha-poly EtA
     */

    typedef enum
    {
        MBEDTLS_CHACHAPOLY_ENCRYPT, /**< The mode value for performing
                                       encryption. */
        MBEDTLS_CHACHAPOLY_DECRYPT  /**< The mode value for performing
                                       decryption. */
    } mbedtls_chachapoly_mode_t;

    typedef struct mbedtls_chachapoly_context
    {
        mbedtls_chacha20_context chacha20_ctx; /**< The ChaCha20 context. */
        mbedtls_poly1305_context poly1305_ctx; /**< The Poly1305 context. */
        uint64_t aad_len;        /**< The length (bytes) of the Additional
                                    Authenticated Data. */
        uint64_t ciphertext_len; /**< The length (bytes) of the ciphertext. */
        int      state;          /**< The current state of the context. */
        mbedtls_chachapoly_mode_t
            mode; /**< Cipher mode (encrypt or decrypt). */
    } mbedtls_chachapoly_context;

    void mbedtls_chachapoly_init(mbedtls_chachapoly_context* ctx);

    void mbedtls_chachapoly_free(mbedtls_chachapoly_context* ctx);

    int  mbedtls_chachapoly_setkey(
         mbedtls_chachapoly_context* ctx, const unsigned char key[32]);

    int mbedtls_chachapoly_starts(mbedtls_chachapoly_context* ctx,
        const unsigned char nonce[12], mbedtls_chachapoly_mode_t mode);

    int mbedtls_chachapoly_update(mbedtls_chachapoly_context* ctx, size_t len,
        const unsigned char* input, unsigned char* output);

    int mbedtls_chachapoly_finish(
        mbedtls_chachapoly_context* ctx, unsigned char mac[16]);

#ifdef __cplusplus
}
#endif

#endif
