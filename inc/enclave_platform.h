#ifndef _ENCLAVE_PLATFORM_H_
#define _ENCLAVE_PLATFORM_H_

#include <abstraction.h>
#include <config.h>

#if defined(__cplusplus) && __cplusplus
extern "C"
{
#endif

typedef struct enclave_node_t
{
    uint8_t               hash[CRYPTO_HASH_SIZE];
    uint8_t               slots[CRYPTO_HASH_SIZE][MAX_SLOTS];
    crypto_hash_context_t loader;
} enclave_node_t;

typedef struct enclave_platform_context_t
{
    crypto_pki_context_t session;
    size_t               n_nodes;
    enclave_node_t       nodes[MAX_ENCLAVES];
} enclave_platform_context_t;

/**
 * @brief Initialize the enclave platform.
 *
 * @note requires `crypto_init()` to be called first.
 */
void            enclave_platform_init();

/**
 * @brief Free the enclave platform.
 */
void            enclave_platform_free();

enclave_node_t* enclave_node_at(size_t node_id);

/**
 * Secure Loader
 */

/**
 * @brief Start loading a chunk.
 */
void            enclave_node_load_start(enclave_node_t* node);

/**
 * @brief Append a chunk of data to the enclave being loaded.
 */
void            enclave_node_load_chunk(
               enclave_node_t* node, uint8_t* chunk, size_t chunk_size);

/**
 * @brief Verify the chunk being loaded.
 */
err_t enclave_node_load_verify(enclave_node_t* node, const uint8_t* sig,
    const uint8_t* dvk_sig, const uint8_t* dvk_pem, size_t dvk_pem_size);

/**
 * @brief Verify the mutual trusted slots.
 */
err_t enclave_node_trust_slots_verify(enclave_node_t* node, const uint8_t* slots,
    const uint8_t* slots_sig, const uint8_t* dvk_pem, size_t dvk_pem_size);

#if defined(__cplusplus) && __cplusplus
};
#endif

#endif /* _ENCLAVE_PLATFORM_H_ */
