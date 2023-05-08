#include <enclave_protocol_dds.h>

static inline void
enclave_dds_populate(
    const enclave_dds_participant_t* me, enclave_dds_header_t* header)
{
    header->id  = me->id;
    header->par = me->par;
}

static inline void
enclave_dds_head_only_msg(enclave_dds_header_t* msg, const enclave_dds_participant_t* me,
    const enum enclave_dds_protocol_t protocol, const enclave_dds_id_t peer_id,
    const enclave_dds_id_t peer_par)
{
    enclave_dds_populate(me, msg);
    msg->protocol       = protocol;
    msg->peer_id        = peer_id;
    msg->peer_par       = peer_par;
    msg->payload_status = EDDS_PAYLOAD_EMPTY;
    msg->length         = ENCLAVE_DDS_HEADER_SIZE;
}

static inline void
enclave_dds_fixed_length_msg(enclave_dds_header_t* msg,
    const enum enclave_dds_protocol_t protocol,
    const enclave_dds_participant_t* me,
    const enclave_dds_id_t peer_id,
    const enclave_dds_id_t peer_par,
    const uint32_t length)
{
    enclave_dds_populate(me, msg);
    msg->protocol       = protocol;
    msg->peer_id        = peer_id;
    msg->peer_par       = peer_par;
    msg->payload_status = EDDS_PAYLOAD_PLAINTEXT;
    msg->length         = length;
}

/******************************************************************************
 * Autenticatable Topic - Subscriber
 ******************************************************************************/

void
enclave_dds_prepare_join(
    const enclave_dds_participant_t* me, enclave_dds_join_t* output)
{
    enclave_dds_populate(me, output);
    enclave_dds_head_only_msg(output, me, EDDS_JOIN, ID_ANY, ID_ANY);
}

void
enclave_dds_auth_on_announce(
    enclave_dds_challenger_ctx_t* const ctx,
    const enclave_dds_participant_t* me,
    const enclave_dds_announce_t* input,
    struct enclave_dds_challenge_t* output)
{
    crypto_assert(input->protocol == EDDS_ANNOUNCE);

    ctx->peer_id  = input->id;
    ctx->peer_par = input->par;

    enclave_ra_challenge(&ctx->att, &output->body);
    enclave_dds_fixed_length_msg(&output->header, EDDS_RA_CHALLENGE, me,
        input->id, input->par, ENCLAVE_DDS_RA_CHALLENGE_MSG_SIZE);
}

err_t
enclave_dds_auth_on_response(
    enclave_dds_challenger_ctx_t* const ctx,
    const enclave_dds_ra_response_t* input,
    const uint8_t* remote_hash,
    const uint8_t* device_rvk_pem,
    const size_t device_rvk_pem_size)
{
    crypto_assert(input->header.protocol == EDDS_RA_RESPONSE);
    crypto_assert(input->header.length == ENCLAVE_DDS_RA_RESPONSE_MSG_SIZE);

    err_t rv = enclave_ra_verify(&ctx->att, remote_hash, device_rvk_pem,
        device_rvk_pem_size, &input->body);
    if (rv != ERR_OK)
    {
        return rv;
    }

    enclave_endpoint_derive_from_attestation(&ctx->att, &ctx->ep);
    return ERR_OK;
}

err_t
enclave_dds_on_notify(
    enclave_dds_challenger_ctx_t * const ctx,
    const enclave_dds_notify_t* input,
    enclave_endpoint_context_t* grp_ep)
{
    crypto_assert(input->header.protocol == EDDS_NOTIFY);
    crypto_assert(input->header.length == ENCLAVE_DDS_NOTIFY_MSG_SIZE);

    err_t err;
    uint8_t grp_key[ENCLAVE_DDS_GROUP_KEY_SIZE];
    err = enclave_endpoint_unseal(&ctx->ep, &input->body.object, grp_key);

    if (err != ERR_OK)
    {
        goto cleanup;
    }
    enclave_endpoint_derive_from_key(grp_ep, grp_key);
cleanup:
    enclave_endpoint_free(&ctx->ep);
    return err;
}

err_t enclave_dds_prepare_msg(
    enclave_endpoint_context_t * const grp_ep,
    const enclave_dds_participant_t* me,
    const uint8_t* plaintext, const size_t plaintext_size,
    enclave_dds_msg_t * const msg, const size_t msg_size, size_t * actual_size)
{
    crypto_assert(grp_ep != NULL);
    crypto_assert(plaintext != NULL);
    crypto_assert(plaintext_size > 0);
    crypto_assert(msg != NULL);
    crypto_assert(actual_size != NULL);

    size_t len = ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext_size);
    err_t err = ERR_OK;
    if (msg_size < len)
    {
        err = ERR_INVALID_SIZE;
        goto cleanup;
    }

    enclave_endpoint_seal(grp_ep, plaintext, plaintext_size, &msg->body.object);
    enclave_dds_fixed_length_msg(&msg->header, EDDS_MSG, me, ID_ANY, ID_ANY, len);
    msg->header.payload_status = EDDS_PAYLOAD_AEAD;
    *actual_size = len;

cleanup:
    return err;
}

err_t
enclave_dds_on_msg(
    enclave_endpoint_context_t* const grp_ep,
    const enclave_dds_msg_t* input,
    uint8_t* const output)
{
    crypto_assert(input->header.protocol == EDDS_MSG);
    crypto_assert(input->header.length == ENCLAVE_DDS_MSG_SIZE(input->body.object.header.size));

    err_t err;
    err = enclave_endpoint_unseal(grp_ep, &input->body.object, output);
    return err;
}

/******************************************************************************
 * Autenticatable Topic - Publisher
 ******************************************************************************/

err_t
enclave_dds_on_join(const enclave_dds_participant_t* me,
    const enclave_dds_join_t* input, enclave_dds_announce_t* output)
{
    crypto_assert(input->protocol == EDDS_JOIN);
    if ((input->peer_id == ID_ANY && input->peer_par == ID_ANY)
        || (input->peer_id == me->id && input->peer_par == me->par))
    {
        enclave_dds_head_only_msg(
            output, me, EDDS_ANNOUNCE, input->id, input->par);
        return ERR_OK;
    }

    return ERR_INVALID_ID;
}

void
enclave_dds_prepare_announce(
    const enclave_dds_participant_t* me, enclave_dds_announce_t* output)
{
    enclave_dds_head_only_msg(output, me, EDDS_ANNOUNCE, ID_ANY, ID_ANY);
}

void
enclave_dds_auth_on_challenge(const enclave_dds_participant_t* me,
    const uint8_t* grp_key, const enclave_dds_ra_challenge_t* input,
    enclave_dds_ra_response_t* response, enclave_dds_notify_t* notification)
{
    crypto_assert(input->header.protocol == EDDS_RA_CHALLENGE);
    crypto_assert(input->header.length == ENCLAVE_DDS_RA_CHALLENGE_MSG_SIZE);

    enclave_endpoint_context_t ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_ra_response(me->id, &input->body, &response->body, &ep);
    enclave_dds_fixed_length_msg(&response->header, EDDS_RA_RESPONSE, me,
        input->header.id, input->header.par,
        ENCLAVE_DDS_RESPONSE_MSG_SIZE);

    enclave_endpoint_seal(
        &ep, grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE, &notification->body.object);
    enclave_dds_fixed_length_msg(&notification->header, EDDS_NOTIFY, me,
        input->header.id, input->header.par,
        ENCLAVE_DDS_NOTIFY_MSG_SIZE);
    notification->header.payload_status = EDDS_PAYLOAD_AEAD;

    enclave_endpoint_free(&ep);
}

/******************************************************************************
 * Private Topic - Subscriber
 ******************************************************************************/

void enclave_dds_priv_on_announce(enclave_dds_challenger_ctx_t * ctx,
    enclave_dds_participant_t * me, const enclave_dds_announce_t * input,
    struct enclave_dds_challenge_t * output)
{
    crypto_assert(input->protocol == EDDS_ANNOUNCE);

    ctx->peer_id  = input->id;
    ctx->peer_par = input->par;

    enclave_ma_initiator_challenge(&ctx->att, &output->body);
    enclave_dds_fixed_length_msg(&output->header, EDDS_MA_CHALLENGE, me,
        input->id, input->par, ENCLAVE_DDS_MA_CHALLENGE_MSG_SIZE);
}

err_t
    enclave_dds_priv_on_challenge_response(enclave_dds_challenger_ctx_t * ctx,
        const enclave_dds_participant_t * me,
        const enclave_dds_ma_challenge_response_t * input,
        const uint8_t * remote_hash,
        const uint8_t * device_rvk_pem,
        const size_t device_rvk_pem_size,
        enclave_dds_ma_response_t * output)
{
    crypto_assert(input->header.protocol == EDDS_MA_CHALLENGE_RESPONSE);
    crypto_assert(input->header.length == ENCLAVE_DDS_MA_CHALLENGE_RESPONSE_MSG_SIZE);

    err_t rv;
    rv = enclave_ma_initiator_response(&ctx->att, me->id, remote_hash,
        device_rvk_pem, device_rvk_pem_size, &input->body, &output->body);
    if (rv != ERR_OK)
    {
        enclave_attestation_free(&ctx->att);
        return rv;
    }
    enclave_dds_fixed_length_msg(&output->header, EDDS_MA_RESPONSE, me,
        input->header.id, input->header.par, ENCLAVE_DDS_MA_RESPONSE_MSG_SIZE);
    enclave_endpoint_derive_from_attestation(&ctx->att, &ctx->ep);
    return ERR_OK;
}

/******************************************************************************
 * Private Topic - Publisher
 ******************************************************************************/

void enclave_dds_priv_on_challenge(
    enclave_dds_challenger_ctx_t * ctx,
    const enclave_dds_participant_t * me,
    const enclave_dds_ma_challenge_t * input,
    enclave_dds_ma_challenge_response_t * output)
{
    crypto_assert(input->header.protocol == EDDS_MA_CHALLENGE);
    crypto_assert(input->header.length == ENCLAVE_DDS_MA_CHALLENGE_MSG_SIZE);

    enclave_ma_responder_response(&ctx->att, me->id, &input->body, &output->body);
    enclave_dds_fixed_length_msg(&output->header, EDDS_MA_CHALLENGE_RESPONSE,
        me, input->header.id, input->header.par,
        ENCLAVE_DDS_MA_CHALLENGE_RESPONSE_MSG_SIZE);
}

err_t enclave_dds_priv_on_response(
    enclave_dds_challenger_ctx_t * ctx,
    const enclave_dds_participant_t * me,
    const uint8_t * grp_key,
    const uint8_t * remote_hash,
    const uint8_t * device_rvk_pem,
    const size_t device_rvk_pem_size,
    const enclave_dds_ma_response_t * input,
    enclave_dds_notify_t * notification)
{
    crypto_assert(input->header.protocol == EDDS_MA_RESPONSE);
    crypto_assert(input->header.length == ENCLAVE_DDS_MA_RESPONSE_MSG_SIZE);

    err_t rv;
    rv = enclave_ma_responder_verify(&ctx->att, remote_hash, device_rvk_pem,
        device_rvk_pem_size, &input->body);
    if (rv != ERR_OK)
    {
        enclave_attestation_free(&ctx->att);
        return rv;
    }
    enclave_endpoint_derive_from_attestation(&ctx->att, &ctx->ep);
    enclave_endpoint_seal(&ctx->ep, grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE,
        &notification->body.object);
    enclave_dds_fixed_length_msg(&notification->header, EDDS_NOTIFY, me,
        input->header.id, input->header.par,
        ENCLAVE_DDS_NOTIFY_MSG_SIZE);
    notification->header.payload_status = EDDS_PAYLOAD_AEAD;

    enclave_endpoint_free(&ctx->ep);
    enclave_attestation_free(&ctx->att);
    return ERR_OK;
}
