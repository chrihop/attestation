#ifndef _ENCLAVE_COMMON_H_
#define _ENCLAVE_COMMON_H_

#include <abstraction.h>
#include <config.h>

#if defined(__cplusplus) && __cplusplus
extern "C"
{
#endif

typedef struct enclave_node_t
{
    size_t                node_id;
    size_t                par_id;
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

enclave_node_t * enclave_node_create(size_t par_id);

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

/**
 * Attestation Facilities
 *
 * \verbatim
 * (1)propose()->[challenge]
 *
 *     +----+
 *     |    |
 *     |  +-v-+   (2)send[chall.]  +---+
 *     +--+ A |<------------------>| B |
 *        +---+   (5)recv[report]  ++--+
 *                                  | ^
 * (6)verify(challenge)             | |
 *                       (3)report()| |   (4)signed
 *                                  v |     [report]
 *                          +---------+--------+
 *                          | Enclave Platform |
 *                          +------------------+
 * \endverbatim
 */

#define ENCLAVE_ATTESTATION_NONCE_SIZE     (12)

typedef struct enclave_node_report_body_t
{
    uint32_t id, par;
    uint8_t  nonce[ENCLAVE_ATTESTATION_NONCE_SIZE];
    uint8_t  dh[CRYPTO_DH_PUBKEY_SIZE];
    uint8_t  hash[CRYPTO_HASH_SIZE];
    uint8_t  session_pubkey[CRYPTO_DS_PUBKEY_SIZE];
    uint8_t  session_sig[CRYPTO_DS_SIGNATURE_SIZE];
} __attribute__((packed)) enclave_node_report_body_t;

#define ENCLAVE_NODE_REPORT_BODY_SIZE (sizeof(enclave_node_report_body_t))

typedef struct enclave_node_report_t
{
    enclave_node_report_body_t b;
    uint8_t report_sig[CRYPTO_DS_SIGNATURE_SIZE];
} __attribute__((packed)) enclave_node_report_t;

#define ENCLAVE_NODE_REPORT_SIZE   (sizeof(enclave_node_report_t))

void  enclave_node_report(struct enclave_node_t* node, const uint8_t* nonce,
     const uint8_t* dh, enclave_node_report_t* report);

err_t enclave_report_verify(const enclave_node_report_t* report,
    const uint8_t* nonce, const uint8_t* hash, const uint8_t* rvk_pem,
    size_t rvk_pem_size);

static inline void
enclave_node_report_by_node(uint32_t node_id, const uint8_t* nonce, const uint8_t* dh, enclave_node_report_t* report)
{
    crypto_assert(node_id < MAX_ENCLAVES);
    enclave_node_t * node = enclave_node_at(node_id);

    enclave_node_report(node, nonce, dh, report);
}

enum enclave_attestation_type_t
{
    EAI_TYPE_REMOTE,
    EAI_TYPE_MUTUAL,
    EAI_TYPE_LOCAL
};

/**
 * Attestation Common
 *
 * \verbatim
 *
 * - remote attestation:
 *
 *   Client: INIT -[send challenge]-> CHALLENGE -[recv report]-> FINISH
 *                -[derive endpoint]-> INIT
 *
 *   Enclave: INIT -[recv challenge; send report]-> FINISH
 *                 -[derive endpoint]-> INIT
 *
 * - mutual attestation:
 *
 *   Initiator: INIT -[send challenge]-> CHALLENGE
 *                   -[recv challenge report; send report]-> FINISH
 *                   -[derive endpoint]-> INIT
 *
 *   Responder: INIT -[recv challenge; send challenge report]-> CHALLENGE
 *                   -[recv report]-> FINISH
 *                   -[derive endpoint]-> INIT
 *
 * - local attestation:
 *
 *   the same as mutual attestation
 *
 * \endverbatim
 *
 */
enum enclave_attestation_step_t
{
    EAI_STEP_INIT,
    EAI_STEP_CHALLENGE,
    EAI_STEP_FINISH,
    EAI_STEP_FAILED
};

typedef struct enclave_attestation_context_t
{
    enum enclave_attestation_step_t step;
    crypto_dh_context_t dh;
    uint32_t peer_node, peer_par;
    uint8_t nonce[ENCLAVE_ATTESTATION_NONCE_SIZE];
} enclave_attestation_context_t;

#define ENCLAVE_ATTESTATION_CONTEXT_INIT \
    {                                    \
        .step = EAI_STEP_INIT,           \
        .dh = CRYPTO_DH_CONTEXT_INIT     \
    }

typedef struct enclave_attestation_challenge_t
{
    enum enclave_attestation_type_t type;
    uint32_t node, par;
    uint8_t  nonce[ENCLAVE_ATTESTATION_NONCE_SIZE];
    uint8_t  dh[CRYPTO_DH_PUBKEY_SIZE];
} __attribute__((packed)) enclave_attestation_challenge_t;

#define ENCLAVE_ATTESTATION_CHALLENGE_SIZE (sizeof(enclave_attestation_challenge_t))

/**
 * Enclave communication endpoints
 */
enum enclave_endpoint_status_t
{
    EES_INIT,
    EES_ESTABLISHED,
    EES_FAILED
};

typedef struct enclave_endpoint_context_t
{
    enum enclave_endpoint_status_t status;
    crypto_aead_context_t aead;
    uint32_t peer_id, peer_par;
    uint32_t node_id, node_par;
    uint32_t timestamp;
} enclave_endpoint_context_t;

#define ENCLAVE_ENDPOINT_CONTEXT_INIT                                          \
    {                                                                          \
        .status = EES_INIT,                                                    \
        .aead = CRYPTO_AEAD_CONTEXT_INIT,                                      \
        .timestamp = 0,                                                        \
    }

/**
 * Attestation common
 */
void enclave_attestation_free(enclave_attestation_context_t* ctx);

void enclave_endpoint_derive_from_attestation(enclave_attestation_context_t* ctx,
    enclave_endpoint_context_t* endpoint);

/**
 * Remote attestation
 */

void enclave_ra_challenge(enclave_attestation_context_t* ctx,
    enclave_attestation_challenge_t * challenge);

err_t enclave_ra_verify(enclave_attestation_context_t* ctx,
    const uint8_t * remote_binary,
    const uint8_t * remote_rvk_pem, size_t remote_rvk_pem_size,
    const enclave_node_report_t * report);

void enclave_ra_response(
    uint32_t node_id,
    const enclave_attestation_challenge_t * challenge,
    enclave_node_report_t * report,
    enclave_endpoint_context_t * endpoint);

/**
 * Mutual attestation
 */
void enclave_ma_initiator_challenge(enclave_attestation_context_t* ctx,
    enclave_attestation_challenge_t * challenge);

void enclave_ma_responder_response(enclave_attestation_context_t* ctx,
    uint32_t node_id,
    const enclave_attestation_challenge_t * challenge,
    enclave_node_report_t * report);

err_t enclave_ma_initiator_response(
    enclave_attestation_context_t* ctx,
    uint32_t node_id,
    const uint8_t * peer_binary,
    const uint8_t * peer_rvk_pem, size_t peer_rvk_pem_size,
    const enclave_node_report_t * challenge_report,
    enclave_node_report_t * report);

err_t enclave_ma_responder_verify(
    enclave_attestation_context_t* ctx,
    const uint8_t * remote_binary,
    const uint8_t * remote_rvk_pem, size_t remote_rvk_pem_size,
    const enclave_node_report_t * report);


/**
 * Local attestation
 */

void enclave_la_initiator_challenge(enclave_attestation_context_t* ctx,
    enclave_attestation_challenge_t * challenge);

void enclave_la_responder_response(enclave_attestation_context_t* ctx,
    uint32_t node_id,
    const enclave_attestation_challenge_t * challenge,
    enclave_node_report_t * report);

err_t enclave_la_initiator_response(
    enclave_attestation_context_t* ctx,
    uint32_t node_id,
    const uint8_t * peer_binary,
    const enclave_node_report_t * challenge_report,
    enclave_node_report_t * report);

err_t enclave_la_responder_verify(
    enclave_attestation_context_t* ctx,
    const uint8_t * remote_binary,
    const enclave_node_report_t * report);

/**
 * Enclave communication endpoints
 */
#define plain
#define authenticated
#define sealed

typedef struct enclave_message_header_t {
    plain uint32_t sequence;
    plain uint8_t nonce[ENCLAVE_ATTESTATION_NONCE_SIZE];
    authenticated uint32_t node_par __attribute((aligned(8)));
    authenticated uint32_t node_id;
    authenticated uint32_t size;
} __attribute((packed)) enclave_message_header_t;

#define ENCLAVE_MESSAGE_HEADER_SIZE sizeof(enclave_message_header_t)

#define ENCLAVE_MESSAGE_AUTH_SIZE \
    (offsetof(enclave_message_header_t, size) - offsetof(enclave_message_header_t, node_par))

typedef struct enclave_message_t {
    enclave_message_header_t header;
    sealed uint8_t data[];
} __attribute((packed)) enclave_message_t;

#define ENCLAVE_MESSAGE_SIZE(size) (ENCLAVE_MESSAGE_HEADER_SIZE + \
    CRYPTO_AEAD_CIPHERTEXT_SIZE(size))

void enclave_endpoint_init(enclave_endpoint_context_t * ep,
    uint32_t node_id, uint32_t node_par);

void enclave_endpoint_seal(enclave_endpoint_context_t * ep,
    const uint8_t * data, size_t size, enclave_message_t * output);

err_t enclave_endpoint_unseal(enclave_endpoint_context_t * ep,
    const enclave_message_t * input, uint8_t * output);

void enclave_endpoint_derive_from_key(enclave_endpoint_context_t * ep,
    const uint8_t * key);

void enclave_endpoint_derive_from_endpoint(enclave_endpoint_context_t * ep,
    const enclave_endpoint_context_t * peer);

void enclave_endpoint_free(enclave_endpoint_context_t * ep);

#if defined(__cplusplus) && __cplusplus
};
#endif

#endif /* _ENCLAVE_COMMON_H_ */
