#include <mbedtls/platform.h>

#include <enclave_platform.h>

static enclave_platform_context_t epc;

static void enclave_nodes_mgmt_init(void)
{
    epc.n_nodes = 0;
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
 * Remote Attestation
 * - remote attestation [RA]
 * - mutual attestation [MA]
 */

static void
enclave_node_report(
    struct enclave_node_t* node, const uint8_t* dh, uint8_t* report)
{
    crypto_assert(node != NULL);
    crypto_assert(dh != NULL);
    crypto_assert(report != NULL);

}

