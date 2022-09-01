#ifndef _KERN_ENCLAVE_H_
#define _KERN_ENCLAVE_H_

#ifdef _STD_LIBC_
#include <crypto/crypto.h>
#include <stddef.h>
#else
#include <lib/crypto/crypto.h>
#endif

/**
 * Key Management
 */
struct enclave_key_store_t
{
    bool                        has_root;
    struct crypto_ds_context_t  device_key;
    struct crypto_pki_context_t session;
};

struct enclave_key_verifier_t
{
    bool                          loaded;
    struct crypto_ds_public_key_t session_pubkey;
    struct crypto_ds_context_t    session;
    struct crypto_ds_context_t    remote_device;
};

struct enclave_key_report_t
{
    struct crypto_ds_public_key_t session_pubkey;
    struct crypto_ds_signature_t  sig_session;
    struct crypto_ds_signature_t  sig_binary;
    struct crypto_ds_signature_t  sig_dh;
};

#define ENCLAVE_KEY_MAX_SESSIONS      32
#define ENCLAVE_KEY_SESSION_NOT_FOUND ENCLAVE_KEY_MAX_SESSIONS

struct enclave_session_mgmt_t
{
    struct enclave_key_verifier_t sessions[ENCLAVE_KEY_MAX_SESSIONS];
    size_t                        n_sessions;
};

err_t  enclave_key_native(struct enclave_key_store_t* ctx);

/* verify endorsement certificate from another device */
bool   enclave_key_remote(struct enclave_key_verifier_t* ctx,
      struct crypto_ds_public_key_t*                     remote_device,
      struct crypto_ds_public_key_t*                     session_key,
      struct crypto_ds_signature_t*                      session_signature);

void   enclave_key_verifier_free(struct enclave_key_verifier_t* ctx);

err_t  enclave_key_generate_report(struct enclave_key_store_t* ctx,
     struct crypto_dh_curve_t* curve, struct crypto_dh_key_t* shared,
     struct crypto_ds_signature_t* sig_binary,
     struct enclave_key_report_t*  report);

bool   enclave_key_verify_report(struct enclave_key_verifier_t* ctx,
      struct crypto_dh_curve_t* curve, struct crypto_dh_key_t* shared,
      struct crypto_ds_signature_t* sig_dh,
      struct crypto_ds_signature_t* sig_binary, unsigned char sha256_binary[32]);

void   enclave_session_mgmt_init(struct enclave_session_mgmt_t* mgmt);

size_t enclave_session_mgmt_find(struct enclave_session_mgmt_t* mgmt,
    struct crypto_ds_public_key_t*                              session_key);

size_t enclave_session_mgmt_find_empty(struct enclave_session_mgmt_t* mgmt);

size_t enclave_session_mgmt_get(struct enclave_session_mgmt_t* mgmt,
    struct crypto_ds_public_key_t*                             remote_device,
    struct crypto_ds_public_key_t*                             session_key,
    struct crypto_ds_signature_t* session_signature);

void   enclave_session_mgmt_free(
      struct enclave_session_mgmt_t* mgmt, size_t session_idx);

/**
 * Secure Loader
 */
struct enclave_loader_t
{
    bool                          in_use;
    crypto_hash_context_t         sha256_ctx;
    unsigned char                 sha256_hash[32];
    struct crypto_ds_context_t    developer_ctx;
    struct crypto_ds_public_key_t developer_pubkey;
    struct crypto_ds_signature_t  sig;
};

err_t enclave_loader_start(struct enclave_loader_t* ctx);

err_t enclave_loader_add(
    struct enclave_loader_t* ctx, unsigned char* data, size_t len);

bool enclave_loader_report(struct enclave_loader_t* ctx,
    struct enclave_key_store_t* rot, unsigned char* developer_pk_pem,
    size_t developer_pk_len, unsigned char* sig_device_auth_b64,
    size_t sig_device_auth_b64_len, unsigned char* sig_binary_b64,
    size_t                        sig_binary_b64_len,
    struct crypto_ds_signature_t* sig_binary_session);

/**
 * Remote Attestation
 */
struct enclave_attestation_challenge_t
{
    bool                       in_use;
    struct crypto_dh_context_t dh_ctx;
    struct crypto_dh_curve_t   curve;
};

struct enclave_attestation_report_t
{
    struct crypto_dh_key_t      shared_key;
    struct enclave_key_report_t cert;
};

struct crypto_dh_curve_t* enclave_ra_challenge(
    struct enclave_attestation_challenge_t* ctx);

err_t enclave_ra_response(in struct crypto_dh_context_t* ctx,
    in struct enclave_key_store_t* rot, in struct crypto_dh_curve_t* curve,
    in struct crypto_ds_signature_t*         sig_binary,
    out struct enclave_attestation_report_t* report,
    out struct crypto_dh_key_t*              secrete_key);

bool  enclave_ra_verify(in struct enclave_attestation_challenge_t* ctx,
     in struct enclave_session_mgmt_t*                             mgmt,
     in struct crypto_ds_public_key_t*                             remote_device,
     in unsigned char                        hash_binary[32],
     in struct enclave_attestation_report_t* report,
     out struct crypto_dh_key_t*             secrete_key);

#ifdef _KERN_
/* only linked with kernel */
#include <lib/common.h>
#include <lib/elf.h>
#include <lib/pool.h>

#define INVALID_ENCLAVE MAX_ENCLAVES

#ifdef DEBUG_ENCLAVE

#define ENCLAVE_DEBUG(fmt, ...)                                                \
    do                                                                         \
    {                                                                          \
        KERN_DEBUG("Enclave: " fmt, ##__VA_ARGS__);                            \
    } while (0)

#else

#define ENCLAVE_DEBUG(fmt, ...)                                                \
    do                                                                         \
    {                                                                          \
    } while (0)

#endif

typedef uint32_t enclave_id_t;

struct enclave_endpoint_t
{
    struct crypto_dh_key_t     key;
    struct crypto_sc_context_t ctx;
};

struct enclave_t
{
    bool  secure; /**< is enclave loaded with secure loader */
    pid_t pid;    /**< pid of the enclave */
    struct crypto_ds_signature_t
        signature; /**< binary signature that is signed by the session key */
    struct enclave_attestation_challenge_t
        challenger; /**< to attest a remote enclave */
    struct crypto_dh_context_t
        responder; /**< to response to a remote enclave */
    struct enclave_attestation_report_t
        report; /**< a report to response to remote attestation */
    struct enclave_endpoint_t endpoints[32];
};

struct enclave_pool_t
{
    struct enclave_t       enclaves[MAX_ENCLAVES];
    bool                   alloc[MAX_ENCLAVES];
    struct circular_pool_t pool;
};

extern struct enclave_pool_t enclave_pool;

gcc_inline void
enclave_pool_init(struct enclave_pool_t* ep)
{
    memset(ep, 0, sizeof(struct enclave_t) * MAX_ENCLAVES);
    circular_pool_init(&ep->pool, ep->alloc, MAX_ENCLAVES);
}

gcc_inline enclave_id_t
enclave_pool_alloc(struct enclave_pool_t* ep, pid_t pid)
{
    enclave_id_t eid = circular_pool_alloc(&ep->pool);
    if (eid < MAX_ENCLAVES)
    {
        ep->enclaves[eid].pid = pid;
        return (eid);
    }

    return (MAX_ENCLAVES);
}

gcc_inline void
enclave_pool_free(struct enclave_pool_t* ep, enclave_id_t eid)
{
    circular_pool_free(&ep->pool, eid);
}

gcc_inline struct enclave_t*
enclave_pool_get_enclave(struct enclave_pool_t* ep, enclave_id_t eid)
{
    return (&ep->enclaves[eid]);
}

struct enclave_platform_t
{
    struct enclave_key_store_t    root_of_trust;
    struct crypto_ds_public_key_t device_identity;
    struct enclave_session_mgmt_t remote;
    struct enclave_loader_t       loader[MAX_CPU];
    enclave_id_t                  enclave_id[MAX_THREADS];
};

extern struct enclave_platform_t enclave_platform;

void                             enclave_platform_init(void);

void                             elf_load_secure_callback(
                                uintptr_t start, size_t length, enum elf_load_actions action);

enclave_id_t       enclave_elf_load(uintptr_t exe_ptr, pid_t pid);

gcc_code_hot pid_t enclave_create(uintptr_t elf, uint32_t quota);

#if (KCONF_ENCLAVE == YES)
#include <arch/enclave.h>

gcc_inline void
enclave_init(uintptr_t bl_params_addr)
{
    arch_enclave_init(bl_params_addr);
}

gcc_inline void
enclave_boot_untrusted()
{
    arch_enclave_boot_untrusted();
}

#endif
#endif /* _KERN_ */

#endif /* _KERN_ENCLAVE_H_ */
