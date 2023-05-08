#include <enclave_common.h>

enum enclave_dds_protocol_t
{
    EDDS_JOIN,
    EDDS_ANNOUNCE,
    EDDS_RA_CHALLENGE,
    EDDS_RA_RESPONSE,
    EDDS_MA_CHALLENGE,
    EDDS_MA_CHALLENGE_RESPONSE,
    EDDS_MA_RESPONSE,
    EDDS_NOTIFY,
    EDDS_MSG,
};

enum enclave_dds_payload_status_t
{
    EDDS_PAYLOAD_EMPTY,
    EDDS_PAYLOAD_PLAINTEXT,
    EDDS_PAYLOAD_HMAC,
    EDDS_PAYLOAD_AEAD,
};

typedef int32_t enclave_dds_id_t;
#define ID_ANY ((enclave_dds_id_t)-1)

typedef struct enclave_dds_participant_t
{
    enclave_dds_id_t par, id;
} enclave_dds_participant_t;

typedef struct enclave_dds_header_t
{
    enum enclave_dds_protocol_t       protocol;
    enclave_dds_id_t                  id, par;
    enclave_dds_id_t                  peer_id, peer_par;
    enum enclave_dds_payload_status_t payload_status;
    uint32_t                          length;
} __attribute((packed)) enclave_dds_header_t;

#define ENCLAVE_DDS_HEADER_SIZE sizeof(struct enclave_dds_header_t)

#define ENCLAVE_DDS_HEAD_ONLY_MSG(protocol, id, par, peer_id, peer_par)        \
    (enclave_dds_header_t)                                                     \
    {                                                                          \
        .protocol = protocol, .id = id, .par = par, .peer_id = peer_id,        \
        .peer_par = peer_par, .payload_status = EDDS_PAYLOAD_EMPTY,            \
        .length = ENCLAVE_DDS_HEADER_SIZE,                                     \
    }

#define ENCLAVE_DDS_FIXED_LENGTH_MSG(                                          \
    protocol, id, par, peer_id, peer_par, length)                              \
    (enclave_dds_header_t)                                                     \
    {                                                                          \
        .protocol = protocol, .id = id, .par = par, .peer_id = peer_id,        \
        .peer_par = peer_par, .payload_status = EDDS_PAYLOAD_PLAINTEXT,        \
        .length = ENCLAVE_DDS_HEADER_SIZE + length,                            \
    }

typedef enclave_dds_header_t enclave_dds_join_t;

#define ENCLAVE_DDS_JOIN_MSG_SIZE sizeof(struct enclave_dds_join_t)

#define ENCLAVE_DDS_JOIN_MSG(sub_id, sub_par)                                  \
    ENCLAVE_DDS_HEAD_ONLY_MSG(EDDS_JOIN, sub_id, sub_par, ID_ANY, ID_ANY)

typedef enclave_dds_header_t enclave_dds_announce_t;

#define ENCLAVE_DDS_ANNOUNCE_MSG_SIZE sizeof(struct enclave_dds_announce_t)

#define ENCLAVE_DDS_ANNOUNCE_PEER_MSG(pub_id, pub_par, peer_id, peer_par)      \
    ENCLAVE_DDS_HEAD_ONLY_MSG(EDDS_ANNOUNCE, pub_id, pub_par, peer_id, peer_par)

#define ENCLAVE_DDS_ANNOUNCE_BROADCAST_MSG(pub_id, pub_par)                    \
    ENCLAVE_DDS_ANNOUNCE_PEER_MSG(pub_id, pub_par, ID_ANY, ID_ANY)

struct enclave_dds_challenge_t
{
    enclave_dds_header_t            header;
    enclave_attestation_challenge_t body;
} __attribute((packed));

#define ENCLAVE_DDS_CHALLENGE_MSG_SIZE sizeof(struct enclave_dds_challenge_t)

typedef struct enclave_dds_challenge_t enclave_dds_ra_challenge_t;
typedef struct enclave_dds_challenge_t enclave_dds_ma_challenge_t;

#define ENCLAVE_DDS_RA_CHALLENGE_MSG_SIZE ENCLAVE_DDS_CHALLENGE_MSG_SIZE
#define ENCLAVE_DDS_MA_CHALLENGE_MSG_SIZE ENCLAVE_DDS_CHALLENGE_MSG_SIZE

#define ENCLAVE_DDS_RA_CHALLENGE_MSG(id, par, peer_id, peer_par)               \
    (enclave_dds_ra_challenge_t)                                               \
    {                                                                          \
        .header = ENCLAVE_DDS_FIXED_LENGTH_MSG(EDDS_RA_CHALLENGE, id, par,     \
            peer_id, peer_par, ENCLAVE_ATTESTATION_CHALLENGE_SIZE),            \
        .body   = { .node = peer_id, .par = peer_par },                        \
    }

#define ENCLAVE_DDS_MA_CHALLENGE_MSG(id, par, peer_id, peer_par)               \
    (enclave_dds_ma_challenge_t)                                               \
    {                                                                          \
        .header = ENCLAVE_DDS_FIXED_LENGTH_MSG(EDDS_MA_CHALLENGE, id, par,     \
            peer_id, peer_par, ENCLAVE_ATTESTATION_CHALLENGE_SIZE),            \
        .body   = { .node = peer_id, .par = peer_par },                        \
    }

struct enclave_dds_response_t
{
    enclave_dds_header_t  header;
    enclave_node_report_t body;
} __attribute((packed));

#define ENCLAVE_DDS_RESPONSE_MSG_SIZE sizeof(struct enclave_dds_response_t)

typedef struct enclave_dds_response_t enclave_dds_ra_response_t;
typedef struct enclave_dds_response_t enclave_dds_ma_challenge_response_t;
typedef struct enclave_dds_response_t enclave_dds_ma_response_t;

#define ENCLAVE_DDS_RA_RESPONSE_MSG_SIZE           ENCLAVE_DDS_RESPONSE_MSG_SIZE
#define ENCLAVE_DDS_MA_CHALLENGE_RESPONSE_MSG_SIZE ENCLAVE_DDS_RESPONSE_MSG_SIZE
#define ENCLAVE_DDS_MA_RESPONSE_MSG_SIZE           ENCLAVE_DDS_RESPONSE_MSG_SIZE

#define ENCLAVE_DDS_RA_RESPONSE_MSG(id, par, peer_id, peer_par)                \
    (enclave_dds_ra_response_t)                                                \
    {                                                                          \
        .header = ENCLAVE_DDS_FIXED_LENGTH_MSG(EDDS_RA_RESPONSE, id, par,      \
            peer_id, peer_par, ENCLAVE_NODE_REPORT_SIZE),                      \
        .body   = { .node = peer_id, .par = peer_par },                        \
    }

#define ENCLAVE_DDS_MA_CHALLENGE_RESPONSE_MSG(id, par, peer_id, peer_par)      \
    (enclave_dds_ma_challenge_response_t)                                      \
    {                                                                          \
        .header = ENCLAVE_DDS_FIXED_LENGTH_MSG(EDDS_MA_CHALLENGE_RESPONSE, id, \
            par, peer_id, peer_par, ENCLAVE_NODE_REPORT_SIZE),                 \
        .body   = { .node = peer_id, .par = peer_par },                        \
    }

#define ENCLAVE_DDS_MA_RESPONSE_MSG(id, par, peer_id, peer_par)                \
    (enclave_dds_ma_response_t)                                                \
    {                                                                          \
        .header = ENCLAVE_DDS_FIXED_LENGTH_MSG(EDDS_MA_RESPONSE, id, par,      \
            peer_id, peer_par, ENCLAVE_NODE_REPORT_SIZE),                      \
        .body   = { .node = peer_id, .par = peer_par },                        \
    }

#define ENCLAVE_DDS_GROUP_KEY_SIZE CRYPTO_AEAD_KEY_SIZE

typedef struct enclave_dds_notify_t
{
    enclave_dds_header_t header;
    union
    {
        uint8_t bytes[ENCLAVE_MESSAGE_SIZE(ENCLAVE_DDS_GROUP_KEY_SIZE)];
        enclave_message_t object;
    } body;
} __attribute((packed)) enclave_dds_notify_t;

#define ENCLAVE_DDS_NOTIFY_MSG_SIZE sizeof(struct enclave_dds_notify_t)

typedef struct enclave_dds_msg_t
{
    enclave_dds_header_t header;
    union
    {
        uint8_t bytes[ENCLAVE_MESSAGE_SIZE(0)];
        enclave_message_t object;
    } body;
} __attribute((packed)) enclave_dds_msg_t;

#define ENCLAVE_DDS_MSG_SIZE(size) (sizeof(enclave_dds_header_t) + \
    ENCLAVE_MESSAGE_SIZE(size))

#define ENCLAVE_DDS_MSG_BODY_OFFSET \
    (offsetof(enclave_dds_msg_t, body.bytes))

static inline enclave_message_t *enclave_dds_msg_body_of(uint8_t *msg)
{
    return (enclave_message_t *)(msg + ENCLAVE_DDS_MSG_BODY_OFFSET);
}

#define ENCLAVE_DDS_MSG_DATA_OFFSET                                       \
    (offsetof(enclave_dds_msg_t, body.object.data))

#define ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext_size) \
    ENCLAVE_DDS_MSG_SIZE(CRYPTO_AEAD_CIPHERTEXT_SIZE(plaintext_size))


enum enclave_dds_topic_type_t
{
    EDDS_TOPIC_NORMAL,
    EDDS_TOPIC_AUTHENTICATABLE,
    EDDS_TOPIC_PRIVATE,
};

typedef struct enclave_dds_challenger_ctx_t
{
    int32_t                              peer_id, peer_par;
    struct enclave_attestation_context_t att;
    struct enclave_endpoint_context_t    ep;
} enclave_dds_challenger_ctx_t;

#define ENCLAVE_DDS_CHALLENGER_CTX_INIT                                        \
    {                                                                          \
        .att = ENCLAVE_ATTESTATION_CONTEXT_INIT,                               \
        .ep  = ENCLAVE_ENDPOINT_CONTEXT_INIT,                                  \
    };

#if defined(__cplusplus) && __cplusplus
extern "C"
{
#endif

/**
 * Autenticatable topic - subscriber
 * */

void enclave_dds_prepare_join(
    const enclave_dds_participant_t* me, enclave_dds_join_t* output);

void  enclave_dds_auth_on_announce(enclave_dds_challenger_ctx_t* const ctx,
     const enclave_dds_participant_t*                                  me,
     const enclave_dds_announce_t*                                     input,
     struct enclave_dds_challenge_t* output);

err_t enclave_dds_auth_on_response(enclave_dds_challenger_ctx_t* const ctx,
    const enclave_dds_ra_response_t* input, const uint8_t* remote_hash,
    const uint8_t* device_rvk_pem, const size_t device_rvk_pem_size);

err_t enclave_dds_on_notify(enclave_dds_challenger_ctx_t* const ctx,
    const enclave_dds_notify_t* input, enclave_endpoint_context_t* grp_ep);

err_t enclave_dds_prepare_msg(
    enclave_endpoint_context_t * const grp_ep,
    const enclave_dds_participant_t* me,
    const uint8_t* plaintext, const size_t plaintext_size,
    enclave_dds_msg_t * const msg, const size_t msg_size, size_t * actual_size);

err_t enclave_dds_on_msg(enclave_endpoint_context_t* const grp_ep,
    const enclave_dds_msg_t* input, uint8_t* const output);

/**
 * Autenticatable topic - publisher
 * */

err_t enclave_dds_on_join(const enclave_dds_participant_t* me,
    const enclave_dds_join_t* input, enclave_dds_announce_t* output);

void  enclave_dds_prepare_announce(
     const enclave_dds_participant_t* me, enclave_dds_announce_t* output);

void  enclave_dds_auth_on_challenge(const enclave_dds_participant_t* me,
     const uint8_t* grp_key, const enclave_dds_ra_challenge_t* input,
     enclave_dds_ra_response_t* response,
     enclave_dds_notify_t* notification);

/**
 * Private topic - subscriber
 * */

void  enclave_dds_priv_on_announce(enclave_dds_challenger_ctx_t* ctx,
     enclave_dds_participant_t* me, const enclave_dds_announce_t* input,
     struct enclave_dds_challenge_t* output);

err_t enclave_dds_priv_on_challenge_response(
    enclave_dds_challenger_ctx_t* ctx, const enclave_dds_participant_t* me,
    const enclave_dds_ma_challenge_response_t* input,
    const uint8_t* remote_hash, const uint8_t* device_rvk_pem,
    const size_t device_rvk_pem_size, enclave_dds_ma_response_t* output);

/**
 * Private topic - publisher
 * */

void  enclave_dds_priv_on_challenge(enclave_dds_challenger_ctx_t* ctx,
     const enclave_dds_participant_t*                             me,
     const enclave_dds_ma_challenge_t*                            input,
     enclave_dds_ma_challenge_response_t*                         output);

err_t enclave_dds_priv_on_response(enclave_dds_challenger_ctx_t* ctx,
    const enclave_dds_participant_t* me, const uint8_t* grp_key,
    const uint8_t* remote_hash, const uint8_t* device_rvk_pem,
    const size_t                     device_rvk_pem_size,
    const enclave_dds_ma_response_t* input,
    enclave_dds_notify_t*            notification);

#if defined(__cplusplus) && __cplusplus
};
#endif
