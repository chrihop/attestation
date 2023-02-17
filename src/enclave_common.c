#include <mbedtls/platform.h>

#include <enclave_platform.h>

static enclave_platform_context_t epc;

static void enclave_nodes_mgmt_init(void)
{
    epc.n_nodes = 0;
    for (size_t i = 0; i < MAX_ENCLAVES; i++)
    {
        epc.nodes[i].node_id = i;
    }
}

static size_t enclave_nodes_mgmt_alloc(void)
{
    crypto_assert(epc.n_nodes < MAX_ENCLAVES);
    return epc.n_nodes++;
}

void enclave_platform_init()
{
    crypto_pki_endorse(crypto_pki_root(), &epc.session);
    enclave_nodes_mgmt_init();
}

void enclave_platform_free()
{
    crypto_pki_free(&epc.session);
    epc.n_nodes = 0;
}

enclave_node_t * enclave_node_create(size_t par_id)
{
    size_t node_id = enclave_nodes_mgmt_alloc();
    enclave_node_t * node = enclave_node_at(node_id);
    node->par_id = par_id;
    return node;
}

enclave_node_t * enclave_node_at(size_t node_id)
{
//    crypto_assert(node_id < epc.n_nodes);
    return &epc.nodes[node_id];
}

void enclave_node_load_start(enclave_node_t * node)
{
    crypto_hash_start(&node->loader);
}

void enclave_node_load_chunk(
    enclave_node_t * node, uint8_t * chunk, size_t chunk_size)
{
    crypto_hash_append(&node->loader, chunk, chunk_size);
}

/**
 * +--------------------------------+
 * |                                |
 * |            Chunk               |
 * |                                |
 * +--------------------------------+
 * | SIG: Sign(Hash(Chunk), DSK)    |
 * +--------------------------------+
 * | DVK: Developer's Verifying Key |
 * +--------------------------------+
 * | DVK_SIG: Sign(DVK, RSK)        |
 * +--------------------------------+
 */
err_t
enclave_node_load_verify(enclave_node_t* node, const uint8_t* sig,
    const uint8_t* dvk_sig, const uint8_t* dvk_pem, size_t dvk_pem_size)
{
    crypto_assert(sig != NULL);
    crypto_assert(dvk_sig != NULL);
    crypto_assert(dvk_pem != NULL);


    err_t err = ERR_OK;
    crypto_hash_report(&node->loader, node->hash);

    uint8_t * dvk       = mbedtls_calloc(1, CRYPTO_DS_PUBKEY_SIZE);
    crypto_assert(dvk != NULL);

    crypto_ds_context_t dds = CRYPTO_DS_CONTEXT_INIT;
    crypto_ds_import_pubkey(&dds, dvk_pem, dvk_pem_size);
    crypto_ds_export_pubkey(&dds, dvk);

    err = crypto_ds_verify(
        &crypto_pki_root()->ds, dvk, CRYPTO_DS_PUBKEY_SIZE, dvk_sig);
    if (err != ERR_OK)
    {
        goto cleanup;
    }

    err = crypto_ds_verify(&dds, node->hash, CRYPTO_HASH_SIZE, sig);
    if (err != ERR_OK)
    {
        goto cleanup;
    }

cleanup:
    crypto_ds_free(&dds);
    mbedtls_free(dvk);

    return err;
}

/**
 * +---------------------------------+
 * |         Trust Slots[0]          |
 * +---------------------------------+
 * |         Trust Slots[1]          |
 * +---------------------------------+
 * |         Trust Slots[2]          |
 * +---------------------------------+
 * |         Trust Slots[3]          |
 * +=================================+
 * |SLOTS_SIG: Sign(Hash(Slots), DSK)|
 * +---------------------------------+
 */
err_t
enclave_node_trust_slots_verify(enclave_node_t* node, const uint8_t* slots,
    const uint8_t* slots_sig, const uint8_t* dvk_pem, size_t dvk_pem_size)
{
    crypto_assert(slots != NULL);
    crypto_assert(slots_sig != NULL);
    crypto_assert(dvk_pem != NULL);

    err_t err = ERR_OK;
    uint8_t * dvk       = mbedtls_calloc(1, CRYPTO_DS_PUBKEY_SIZE);
    crypto_assert(dvk != NULL);

    __builtin_memcpy(node->slots, slots, CRYPTO_HASH_SIZE * MAX_SLOTS);

    crypto_ds_context_t dds;
    crypto_ds_import_pubkey(&dds, dvk_pem, dvk_pem_size);
    crypto_ds_export_pubkey(&dds, dvk);

    err = crypto_ds_verify(
        &dds, (const uint8_t*) node->slots, CRYPTO_HASH_SIZE * MAX_SLOTS, slots_sig);
    if (err != ERR_OK)
    {
        goto cleanup;
    }

cleanup:
    crypto_ds_free(&dds);
    mbedtls_free(dvk);

    return err;
}

/**
 * Attestation Facilities
 * - remote attestation [RA] - non-enclave -> enclave
 * - mutual attestation [MA] - enclave <-> enclave (different ROTs)
 * - local attestation [LA] - enclave <-> enclave (same ROT)
 */

void
enclave_node_report(struct enclave_node_t* node, const uint8_t* nonce,
    const uint8_t* dh, enclave_node_report_t* report)
{
    crypto_assert(node != NULL);
    crypto_assert(dh != NULL);
    crypto_assert(report != NULL);

    report->b.id = node->node_id;
    report->b.par = node->par_id;
    if (nonce == NULL)
    {
        __builtin_memset(report->b.nonce, 0, ENCLAVE_ATTESTATION_NONCE_SIZE);
    }
    else
    {
        __builtin_memcpy(report->b.nonce, nonce, ENCLAVE_ATTESTATION_NONCE_SIZE);
    }
    __builtin_memcpy(report->b.dh, dh, CRYPTO_DH_PUBKEY_SIZE);
    __builtin_memcpy(report->b.hash, node->hash, CRYPTO_HASH_SIZE);
    crypto_ds_export_pubkey(&epc.session.ds, report->b.session_pubkey);
    __builtin_memcpy(report->b.session_sig, epc.session.endorsement, CRYPTO_DS_SIGNATURE_SIZE);
    crypto_ds_sign(&epc.session.ds, (const uint8_t*) &report->b, ENCLAVE_NODE_REPORT_BODY_SIZE, report->report_sig);
}

err_t
enclave_report_verify(const enclave_node_report_t* report,
    const uint8_t * nonce,
    const uint8_t * hash,
    const uint8_t * rvk_pem, size_t rvk_pem_size)
{
    crypto_assert(report != NULL);
    crypto_assert(rvk_pem != NULL);

    err_t err = ERR_OK;
    crypto_ds_context_t rds = CRYPTO_DS_CONTEXT_INIT,
                        sds = CRYPTO_DS_CONTEXT_INIT;
    crypto_ds_import_pubkey(&rds, rvk_pem, rvk_pem_size);

    err = crypto_ds_verify(
        &rds, report->b.session_pubkey, CRYPTO_DS_PUBKEY_SIZE,
        report->b.session_sig);
    if (err != ERR_OK)
    {
        goto cleanup;
    }

    crypto_ds_import_pubkey_psa_format(&sds, report->b.session_pubkey);
    err = crypto_ds_verify(
        &sds, (const uint8_t*) &report->b, ENCLAVE_NODE_REPORT_BODY_SIZE,
        report->report_sig);
    if (err != ERR_OK)
    {
        goto cleanup;
    }

    int rv = __builtin_memcmp(report->b.hash, hash, CRYPTO_HASH_SIZE);
    err = rv == 0 ? ERR_OK : ERR_VERIFICATION_FAILED;

    if (err != ERR_OK)
    {
        goto cleanup;
    }

    if (nonce != NULL)
    {
        rv = __builtin_memcmp(report->b.nonce, nonce, ENCLAVE_ATTESTATION_NONCE_SIZE);
        err = rv == 0 ? ERR_OK : ERR_VERIFICATION_FAILED;
    }

cleanup:
    crypto_ds_free(&rds);
    crypto_ds_free(&sds);

    return err;
}

/**
 * Remote Attestation
 */

void enclave_attestation_free(enclave_attestation_context_t* ctx)
{
    crypto_dh_free(&ctx->dh);
    ctx->step = EAI_STEP_INIT;
}

/**
 * @brief A non-enclave node propose a challenge to an enclave node
 */
void enclave_ra_challenge(enclave_attestation_context_t* ctx,
    enclave_attestation_challenge_t * challenge)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_INIT);

    challenge->type = EAI_TYPE_REMOTE;
    crypto_rng(ctx->nonce, ENCLAVE_ATTESTATION_NONCE_SIZE);
    __builtin_memcpy(challenge->nonce, ctx->nonce, ENCLAVE_ATTESTATION_NONCE_SIZE);
    crypto_dh_propose(&ctx->dh, challenge->dh);
    ctx->step = EAI_STEP_CHALLENGE;
}

/**
 * @brief An non-enclave node verify the challenge from an enclave node
 */
err_t enclave_ra_verify(enclave_attestation_context_t* ctx,
    const uint8_t * remote_binary,
    const uint8_t * remote_rvk_pem, size_t remote_rvk_pem_size,
    const enclave_node_report_t * report)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_CHALLENGE);

    err_t err;
    err = enclave_report_verify(
        report, ctx->nonce, remote_binary, remote_rvk_pem, remote_rvk_pem_size);
    if (err != ERR_OK)
    {
        ctx->step = EAI_STEP_FAILED;
        goto cleanup;
    }

    crypto_dh_exchange(&ctx->dh, report->b.dh);

    ctx->peer_node = report->b.id;
    ctx->peer_par = report->b.par;
    ctx->step = EAI_STEP_FINISH;

cleanup:
    return err;
}

/**
 * @brief An enclave node response to the challenge from a non-enclave node
 *        and generate the shared secret key for communication
 */
void enclave_ra_response(
    uint32_t node_id,
    const enclave_attestation_challenge_t * challenge,
    enclave_node_report_t * report,
    enclave_endpoint_context_t * endpoint)
{
    crypto_assert(challenge != NULL);
    crypto_assert(report != NULL);

    enclave_attestation_context_t ctx = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    crypto_dh_exchange_propose(&ctx.dh, challenge->dh, report->b.dh);
    enclave_node_report_by_node(node_id, challenge->nonce, report->b.dh, report);

    if (endpoint != NULL)
    {
        crypto_dh_derive_aead(&ctx.dh, &endpoint->aead);
        endpoint->peer_id = report->b.id;
        endpoint->peer_par = report->b.par;
    }

    enclave_attestation_free(&ctx);
}

/**
 * @brief A node derive the shared secret key for communication
 */
void enclave_attestation_derive_endpoint(enclave_attestation_context_t* ctx,
    enclave_endpoint_context_t* endpoint)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_FINISH);
    crypto_assert(endpoint != NULL);

    crypto_dh_derive_aead(&ctx->dh, &endpoint->aead);
    endpoint->peer_id = ctx->peer_node;
    endpoint->peer_par = ctx->peer_par;

    enclave_attestation_free(ctx);
    ctx->step = EAI_STEP_INIT;
}

/**
 * Mutual Attestation
 */

/**
 * @brief An enclave node propose a challenge to another enclave node
 */
void enclave_ma_initiator_challenge(enclave_attestation_context_t* ctx,
    enclave_attestation_challenge_t * challenge)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_INIT);

    enclave_ra_challenge(ctx, challenge);
    challenge->type = EAI_TYPE_MUTUAL;
}

/**
 * @brief An enclave node create a [challenge response] to the [challenge] from another enclave node
 */
void enclave_ma_responder_response(enclave_attestation_context_t* ctx,
    uint32_t node_id,
    const enclave_attestation_challenge_t * challenge,
    enclave_node_report_t * report)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_INIT);

    __builtin_memcpy(ctx->nonce, challenge->nonce, ENCLAVE_ATTESTATION_NONCE_SIZE);
    crypto_dh_exchange_propose(&ctx->dh, challenge->dh, report->b.dh);
    enclave_node_report_by_node(node_id, challenge->nonce, report->b.dh, report);

    ctx->peer_node = report->b.id;
    ctx->peer_par = report->b.par;
    ctx->step = EAI_STEP_CHALLENGE;
}

const static uint8_t _enclave_ma_empty_dh[CRYPTO_DH_PUBKEY_SIZE] = {0};

/**
 * @brief An enclave node verify the [challenge response] from another enclave node
 *       and generate a [response] to the enclave node
 */
err_t enclave_ma_initiator_response(
    enclave_attestation_context_t* ctx,
    uint32_t node_id,
    const uint8_t * peer_binary,
    const uint8_t * peer_rvk_pem, size_t peer_rvk_pem_size,
    const enclave_node_report_t * challenge_report,
    enclave_node_report_t * report)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_CHALLENGE);

    err_t err = enclave_report_verify(
        challenge_report, ctx->nonce, peer_binary, peer_rvk_pem, peer_rvk_pem_size);
    if (err != ERR_OK)
    {
        ctx->step = EAI_STEP_FAILED;
        goto cleanup;
    }

    crypto_dh_exchange(&ctx->dh, challenge_report->b.dh);

    ctx->peer_node = challenge_report->b.id;
    ctx->peer_par = challenge_report->b.par;
    ctx->step = EAI_STEP_FINISH;

    enclave_node_report_by_node(node_id, ctx->nonce, _enclave_ma_empty_dh, report);

cleanup:
    return err;
}

/**
 * @brief An enclave node verify the [response] from another enclave node
 */
err_t enclave_ma_responder_verify(
    enclave_attestation_context_t* ctx,
    const uint8_t * remote_binary,
    const uint8_t * remote_rvk_pem, size_t remote_rvk_pem_size,
    const enclave_node_report_t * report)
{
    crypto_assert(ctx != NULL);
    crypto_assert(ctx->step == EAI_STEP_CHALLENGE);
    crypto_assert(remote_binary != NULL);
    crypto_assert(remote_rvk_pem != NULL);
    crypto_assert(report != NULL);

    err_t err = enclave_report_verify(
        report, ctx->nonce, remote_binary, remote_rvk_pem, remote_rvk_pem_size);
    if (err != ERR_OK)
    {
        ctx->step = EAI_STEP_FAILED;
        goto cleanup;
    }
    ctx->step = EAI_STEP_FINISH;

cleanup:
    return err;
}
