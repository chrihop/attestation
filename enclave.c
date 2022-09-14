#ifdef _STD_LIBC_
#include <enclave.h>
#else
#include <enclave.h>
#include <lib/string.h>
#endif

/**
 * Key Management
 */
err_t
enclave_key_native(struct enclave_key_store_t* ctx)
{
    extern unsigned char device_key_pem[];
    extern size_t        device_key_len;

    /* load the device key */
    crypto_ds_import_pem_keypair(
        device_key_pem, device_key_len, NULL, 0, &ctx->device_key);

    /* generate session key */
    crypto_pki_new(&ctx->session, &ctx->device_key);
    ctx->has_root = 1;

    return (ERR_OK);
}

/* verify endorsement certificate from another device */
bool
enclave_key_remote(struct enclave_key_verifier_t* ctx,
    struct crypto_ds_public_key_t*                remote_device,
    struct crypto_ds_public_key_t*                session_key,
    struct crypto_ds_signature_t*                 session_signature)
{
    /* load root key */
    crypto_ds_import_public_key(&ctx->remote_device, remote_device);

    /* load session key */
    int match;
    crypto_verify(&ctx->remote_device, session_key->key, session_key->len,
        session_signature, &match);

    /* prepare session verifier */
    if (match)
    {
        crypto_ds_import_public_key(&ctx->session, session_key);
        memcpy(&ctx->session_pubkey, session_key,
            sizeof(struct crypto_ds_public_key_t));
        ctx->loaded = 1;
    }

    /* free device verification context, no longer needed */
    crypto_ds_free(&ctx->remote_device);
    return match;
}

void
enclave_key_verifier_free(struct enclave_key_verifier_t* ctx)
{
    ctx->loaded = FALSE;
    crypto_ds_free(&ctx->session);
}

err_t
enclave_key_generate_report(struct enclave_key_store_t* ctx,
    struct crypto_dh_curve_t* curve, struct crypto_dh_key_t* shared,
    struct crypto_ds_signature_t* sig_binary,
    struct enclave_key_report_t*  report)
{
    crypto_assert(ctx->has_root == TRUE);

    /* fill pk_s, sig_session, sig_binary */
    memcpy(&report->session_pubkey, &ctx->session.cert.pk,
        sizeof(struct crypto_ds_public_key_t));
    memcpy(&report->sig_session, &ctx->session.cert.sig,
        sizeof(struct crypto_ds_signature_t));
    memcpy(
        &report->sig_binary, sig_binary, sizeof(struct crypto_ds_signature_t));

    /* sign key exchange signature (sig_dh) */
    crypto_hash_init(&ctx->session.client.sha256_ctx);
    crypto_hash_append(
        &ctx->session.client.sha256_ctx, curve->curve, curve->len);
    crypto_hash_append(
        &ctx->session.client.sha256_ctx, shared->key, shared->len);
    crypto_hash_append(&ctx->session.client.sha256_ctx, sig_binary->signature,
        sig_binary->len);
    crypto_hash_report(
        &ctx->session.client.sha256_ctx, ctx->session.client.sha256_hash);

    crypto_sign_hashed(
        &ctx->session.client, ctx->session.client.sha256_hash, &report->sig_dh);

    return (ERR_OK);
}

bool
enclave_key_verify_report(struct enclave_key_verifier_t* ctx,
    struct crypto_dh_curve_t* curve, struct crypto_dh_key_t* shared,
    struct crypto_ds_signature_t* sig_dh,
    struct crypto_ds_signature_t* sig_binary, unsigned char sha256_binary[32])
{
    crypto_assert(ctx->loaded == 1);

    /* verify key exchange signature */
    int match;
    crypto_hash_init(&ctx->session.sha256_ctx);
    crypto_hash_append(&ctx->session.sha256_ctx, curve->curve, curve->len);
    crypto_hash_append(&ctx->session.sha256_ctx, shared->key, shared->len);
    crypto_hash_append(
        &ctx->session.sha256_ctx, sig_binary->signature, sig_binary->len);
    crypto_hash_report(&ctx->session.sha256_ctx, ctx->session.sha256_hash);

    crypto_verify_hashed(
        &ctx->session, ctx->session.sha256_hash, sig_dh, &match);

    if (!match)
    {
        return FALSE;
    }

    /* verify binary hash signature */
    crypto_verify_hashed(&ctx->session, sha256_binary, sig_binary, &match);

    return match;
}

void
enclave_session_mgmt_init(struct enclave_session_mgmt_t* mgmt)
{
    memset(mgmt, 0, sizeof(struct enclave_session_mgmt_t));
}

size_t
enclave_session_mgmt_find(struct enclave_session_mgmt_t* mgmt,
    struct crypto_ds_public_key_t*                       session_key)
{
    size_t i;
    size_t s = ENCLAVE_KEY_SESSION_NOT_FOUND;

    if (mgmt->n_sessions == 0)
    {
        return ENCLAVE_KEY_SESSION_NOT_FOUND;
    }

    for (i = 0; i < ENCLAVE_KEY_MAX_SESSIONS; i++)
    {
        if (0
            == memcmp(session_key->key, mgmt->sessions[i].session_pubkey.key,
                session_key->len))
        {
            s = i;
            break;
        }
    }
    return s;
}

size_t
enclave_session_mgmt_find_empty(struct enclave_session_mgmt_t* mgmt)
{
    size_t i;
    size_t s = ENCLAVE_KEY_SESSION_NOT_FOUND;

    if (mgmt->n_sessions == ENCLAVE_KEY_MAX_SESSIONS - 1)
    {
        return ENCLAVE_KEY_SESSION_NOT_FOUND;
    }

    for (i = 0; i < ENCLAVE_KEY_MAX_SESSIONS; i++)
    {
        if (mgmt->sessions[i].loaded == FALSE)
        {
            s = i;
            break;
        }
    }
    return s;
}

size_t
enclave_session_mgmt_get(struct enclave_session_mgmt_t* mgmt,
    struct crypto_ds_public_key_t*                      remote_device,
    struct crypto_ds_public_key_t*                      session_key,
    struct crypto_ds_signature_t*                       session_signature)
{
    size_t s;
    /* find if the verifier already exists */
    s = enclave_session_mgmt_find(mgmt, session_key);

    if (s != ENCLAVE_KEY_SESSION_NOT_FOUND)
    {
        return s;
    }

    /* not found, load the key */
    s = enclave_session_mgmt_find_empty(mgmt);
    if (s == ENCLAVE_KEY_SESSION_NOT_FOUND)
    {
        /* no empty slot, fail */
        return ENCLAVE_KEY_SESSION_NOT_FOUND;
    }
    struct enclave_key_verifier_t* v = &mgmt->sessions[s];
    bool                           succ
        = enclave_key_remote(v, remote_device, session_key, session_signature);

    if (!succ)
    {
        /* session key verification failed. abort */
        enclave_key_verifier_free(v);
        return ENCLAVE_KEY_SESSION_NOT_FOUND;
    }
    mgmt->n_sessions++;

    return s;
}

void
enclave_session_mgmt_free(
    struct enclave_session_mgmt_t* mgmt, size_t session_idx)
{
    enclave_key_verifier_free(&mgmt->sessions[session_idx]);
    mgmt->n_sessions--;
}

/**
 * Secure Loader
 */
err_t
enclave_loader_start(struct enclave_loader_t* ctx)
{
    crypto_assert(ctx->in_use == FALSE);
    memset(ctx, 0, sizeof(struct enclave_loader_t));
    crypto_hash_init(&ctx->sha256_ctx);
    ctx->in_use = TRUE;

    return (ERR_OK);
}

err_t
enclave_loader_add(
    struct enclave_loader_t* ctx, unsigned char* data, size_t len)
{
    crypto_assert(ctx->in_use == TRUE);
    crypto_hash_append(&ctx->sha256_ctx, data, len);
    return (ERR_OK);
}

bool
enclave_loader_report(struct enclave_loader_t* ctx,
    struct enclave_key_store_t* rot, unsigned char* developer_pk_pem,
    size_t developer_pk_len, unsigned char* sig_device_auth_b64,
    size_t sig_device_auth_b64_len, unsigned char* sig_binary_b64,
    size_t sig_binary_b64_len, struct crypto_ds_signature_t* sig_binary_session)
{
    int match;
    crypto_hash_report(&ctx->sha256_ctx, ctx->sha256_hash);

    crypto_assert(ctx->in_use == TRUE);
    ctx->in_use = FALSE;

    /* verify developer's public key */
    crypto_ds_import_pem_public_key(
        developer_pk_pem, developer_pk_len, &ctx->developer_ctx);
    crypto_ds_export_public_key(&ctx->developer_ctx, &ctx->developer_pubkey);
    crypto_b64_decode(ctx->sig.signature, MBEDTLS_ECDSA_MAX_LEN, &ctx->sig.len,
        sig_device_auth_b64, sig_device_auth_b64_len);
    crypto_verify(&rot->device_key, ctx->developer_pubkey.key,
        ctx->developer_pubkey.len, &ctx->sig, &match);

    if (!match)
    {
        /* unauthorized developer, reject */
        os_printf("developer's signature verification failed!\n");
        crypto_ds_free(&ctx->developer_ctx);
        return (FALSE);
    }

    /* verify binary's hash */
    crypto_b64_decode(ctx->sig.signature, MBEDTLS_ECDSA_MAX_LEN, &ctx->sig.len,
        sig_binary_b64, sig_binary_b64_len);
    crypto_verify_hashed(
        &ctx->developer_ctx, ctx->sha256_hash, &ctx->sig, &match);
    crypto_ds_free(&ctx->developer_ctx);

    if (!match)
    {
        /* corrupted binary, reject */
        os_printf("binary integrity verification failed!\n");
        return (FALSE);
    }

    /* sign the binary with session key */
    crypto_sign_hashed(
        &rot->session.client, ctx->sha256_hash, sig_binary_session);

    return (TRUE);
}

/**
 * Remote Attestation
 */
struct crypto_dh_curve_t*
enclave_ra_challenge(struct enclave_attestation_challenge_t* ctx)
{
    crypto_assert(ctx->in_use == FALSE);
    crypto_dh_genkey(&ctx->dh_ctx, &ctx->curve);
    ctx->in_use = TRUE;
    return (&ctx->curve);
}

err_t
enclave_ra_response(in struct crypto_dh_context_t* ctx,
    in struct enclave_key_store_t* rot, in struct crypto_dh_curve_t* curve,
    in struct crypto_ds_signature_t*         sig_binary,
    out struct enclave_attestation_report_t* report,
    out struct crypto_dh_key_t*              secrete_key)
{
    crypto_dh_exchange_genkey(ctx, curve, &report->shared_key, secrete_key);
    enclave_key_generate_report(
        rot, curve, &report->shared_key, sig_binary, &report->cert);

    return (ERR_OK);
}

bool
enclave_ra_verify(in struct enclave_attestation_challenge_t* ctx,
    in struct enclave_session_mgmt_t*                        mgmt,
    in struct crypto_ds_public_key_t*                        remote_device,
    in unsigned char                                         hash_binary[32],
    in struct enclave_attestation_report_t*                  report,
    out struct crypto_dh_key_t*                              secrete_key)
{
    size_t s;
    crypto_assert(ctx->in_use == TRUE);
    ctx->in_use = FALSE;
    s           = enclave_session_mgmt_get(mgmt, remote_device,
                  &report->cert.session_pubkey, &report->cert.sig_session);
    if (s == ENCLAVE_KEY_SESSION_NOT_FOUND)
    {
        return (FALSE);
    }

    struct enclave_key_verifier_t* v = &mgmt->sessions[s];

    bool                           match;
    match = enclave_key_verify_report(v, &ctx->curve, &report->shared_key,
        &report->cert.sig_dh, &report->cert.sig_binary, hash_binary);
    if (!match)
    {
        return (FALSE);
    }

    crypto_dh_exchange(&ctx->dh_ctx, &report->shared_key, secrete_key);

    return (TRUE);
}

#ifdef _KERN_
/* only linked with kernel */
#include <arch/kstack.h>
#include <proc.h>

struct enclave_platform_t enclave_platform;
struct enclave_pool_t     enclave_pool;

static void
enclave_platform_identity_show(void)
{
    size_t i;
    crypto_ds_export_public_key(&enclave_platform.root_of_trust.device_key,
        &enclave_platform.device_identity);
    crypto_hash_context_t* sha256_ctx
        = &enclave_platform.root_of_trust.device_key.sha256_ctx;
    crypto_hash_init(sha256_ctx);
    crypto_hash_append(sha256_ctx, enclave_platform.device_identity.key,
        enclave_platform.device_identity.len);
    crypto_hash_report(
        sha256_ctx, enclave_platform.root_of_trust.device_key.sha256_hash);
    KERN_INFO("\nDevice Identity: ");
    for (i = 0; i < 32; i++)
    {
        KERN_INFO(
            "%02x", enclave_platform.root_of_trust.device_key.sha256_hash[i]);
    }
    KERN_INFO("\n");
}

void
enclave_platform_init(void)
{
    size_t pid;
    crypto_init();
    enclave_key_native(&enclave_platform.root_of_trust);
    enclave_session_mgmt_init(&enclave_platform.remote);
    for (pid = 0; pid < MAX_THREADS; pid++)
    {
        enclave_platform.enclave_id[pid] = INVALID_ENCLAVE;
    }
    enclave_pool_init(&enclave_pool);

    enclave_platform_identity_show();
}

void
elf_load_secure_callback(
    uintptr_t start, size_t length, enum elf_load_actions action)
{
    cpuid_t cpu = cpu();
    switch (action)
    {
    case ELF_LOAD_START:
        enclave_loader_start(&enclave_platform.loader[cpu]);
        break;
    case ELF_LOAD_PAGE:
        enclave_loader_add(&enclave_platform.loader[cpu], (void*)start, length);
        //		memdump((const void *) start, length);
        break;
    case ELF_LOAD_DONE: break;
    default:
        KERN_PANIC(
            "Error during the secure elf loader. Invalid action (%lu)!\n",
            action);
    }
}

static const char elf_sn_enclave_public_key[] = ".enclave.public_key";
static const char elf_sn_enclave_pubkey_sig[] = ".enclave.pubkey_sig";
static const char elf_sn_enclave_binary_sig[] = ".enclave.binary_sig";

enclave_id_t
enclave_elf_load(uintptr_t exe_ptr, pid_t pid)
{
    cpuid_t   cpu = cpu();

    uintptr_t public_key, pubkey_sig, binary_sig;
    size_t    public_key_sz, pubkey_sig_sz, binary_sig_sz;
    /* load elf file */
    elf_load_internal(exe_ptr, pid, elf_load_secure_callback);

    /* locate signatures */
    public_key
        = elf_find_section(exe_ptr, elf_sn_enclave_public_key, &public_key_sz);
    pubkey_sig
        = elf_find_section(exe_ptr, elf_sn_enclave_pubkey_sig, &pubkey_sig_sz);
    binary_sig
        = elf_find_section(exe_ptr, elf_sn_enclave_binary_sig, &binary_sig_sz);

    if (public_key == NULL_PTR || public_key_sz == 0 || pubkey_sig == NULL_PTR
        || pubkey_sig_sz == 0 || binary_sig == NULL_PTR || binary_sig_sz == 0)
    {
        KERN_WARN("enclave binary 0x%x is not signed. load fail!\n", exe_ptr);
        return (INVALID_ENCLAVE);
    }

    enclave_id_t eid = enclave_pool_alloc(&enclave_pool, pid);
    if (eid >= MAX_ENCLAVES)
    {
        KERN_WARN("enclave pool full. cannot allocate enclaves!\n");
        return (INVALID_ENCLAVE);
    }

    struct enclave_t* e = enclave_pool_get_enclave(&enclave_pool, eid);

    bool              match;
    /* verify binary */
    match = enclave_loader_report(&enclave_platform.loader[cpu],
        &enclave_platform.root_of_trust, (uint8_t*)public_key, public_key_sz,
        (uint8_t*)pubkey_sig, pubkey_sig_sz, (uint8_t*)binary_sig,
        binary_sig_sz, &e->signature);
    if (!match)
    {
        enclave_pool_free(&enclave_pool, eid);
        KERN_WARN("enclave verification failed!\n");
        return (INVALID_ENCLAVE);
    }
    e->secure = TRUE;

    return (eid);
}

gcc_code_hot pid_t
enclave_create(uintptr_t elf, uint32_t quota)
{
    cpuid_t cpu = cpu();

    if (enclave_platform.root_of_trust.has_root == FALSE)
    {
        KERN_WARN("root key is not found! cannot create enclave.\n");
        return INVALID_PID;
    }

    pid_t        pid = thread_spawn(proc_start_user_trapout, quota);
    enclave_id_t eid = enclave_elf_load(elf, pid);
    if (eid >= INVALID_ENCLAVE)
    {
        KERN_WARN("enclave 0x%x (pid = %u) load failed!\n", elf, pid);
        mpt_free_pt(pid);
        container_merge(pid);
        tcb_pool[pid].state = TSTATE_DEAD;
        sched_remove_ready(cpu, pid);
        return INVALID_PID;
    }

    ENCLAVE_DEBUG("enclave 0x%x (pid = %u) load successful!\n", elf, pid);
    mpt_alloc_page(pid, VM_STACKHI - PAGE_SIZE, PP_USER_DATA);
    kstack_init(&proc_kstack[pid], cpu);

    uintptr_t entry = elf_entry(elf);
    kstack_init_user_proc(pid, entry);

    return (pid);
}

#if (KCONF_ENCLAVE == YES)

#endif /* (KCONF_ENCLAVE == YES) */

#endif /* _KERN_ */
