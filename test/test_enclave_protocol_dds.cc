#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <enclave_protocol_dds.h>
#include <vector>
#include <numeric>

using namespace std;

static vector<vector<uint8_t>> elf1_chunks = {
    {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,},
    {0x40, 0x22, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,},
    {0x00, 0x00, 0x00, 0x00, 0x88, 0x24, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,},
    {0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0d, 0x00, 0x40, 0x00,},
    {0x29, 0x00, 0x28, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,},
    {0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,},
};

static uint8_t    elf1_hash[CRYPTO_HASH_SIZE], elf2_hash[CRYPTO_HASH_SIZE];

static vector<vector<uint8_t>> elf2_chunks = {
    {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,},
    {0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,},
    {0x20, 0x9f, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,},
    {0x00, 0x01, 0x00, 0x00, 0xc8, 0xa4, 0x64, 0x01, 0x00, 0x00, 0x00, 0x00,},
    {0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0d, 0x00, 0x40, 0x00,},
};

static const char remote_root_pubkey[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEH6ZLw2s0NqHtnzP83vVdd6sInMk20M0I\n"
    "kZxSA91uBTwrP8FD505M/HDHaJ2tsxQySd+9x/4qlNQCiOpDUb3eTg==\n"
    "-----END PUBLIC KEY-----\0";
static const size_t remote_root_pubkey_size = sizeof(remote_root_pubkey);

static id_t         elf1_load_id = 0;
static id_t         elf2_load_id = 0;

static id_t secure_load(id_t par, vector<vector<uint8_t>> & chunks, uint8_t * hash)
{
    enclave_node_t * node = enclave_node_create(par);
    enclave_node_load_start(node);
    for (auto chunk : chunks) {
        enclave_node_load_chunk(node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&node->loader, node->hash);
    memcpy(hash, node->hash, CRYPTO_HASH_SIZE);
    return node->node_id;
}

class EnclaveDDSProtocolTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        static bool initialized = false;
        if (initialized) {
            return;
        }
        crypto_init();
        enclave_platform_init();
        elf1_load_id = secure_load(1, elf1_chunks, elf1_hash);
        elf2_load_id = secure_load(2, elf2_chunks, elf2_hash);
        printf("elf1 load to %d, elf2 load to %d\n", elf1_load_id, elf2_load_id);
        initialized = true;
    }

    virtual void TearDown() {
    }
};

TEST_F(EnclaveDDSProtocolTest, authenticatable_topic) {
    err_t err;

    enclave_dds_participant_t pub = {.par = 1, .id = (int)elf1_load_id },
                              sub = {.par = 2, .id = 6};

    uint8_t grp_key[ENCLAVE_DDS_GROUP_KEY_SIZE];
    crypto_rng(grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE);

    enclave_endpoint_context_t pub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    enclave_endpoint_derive_from_key(&pub_grp_ep, grp_key);

    enclave_dds_join_t msg_join;
    enclave_dds_prepare_join(&sub, &msg_join);
    EXPECT_EQ(msg_join.protocol, EDDS_JOIN);
    EXPECT_EQ(msg_join.peer_id, ID_ANY);
    EXPECT_EQ(msg_join.peer_par, ID_ANY);
    EXPECT_EQ(msg_join.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_join.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_join.id, sub.id);
    EXPECT_EQ(msg_join.par, sub.par);

    enclave_dds_announce_t msg_announce;
    err = enclave_dds_on_join(&pub, &msg_join, &msg_announce);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(msg_announce.protocol, EDDS_ANNOUNCE);
    EXPECT_EQ(msg_announce.peer_id, sub.id);
    EXPECT_EQ(msg_announce.peer_par, sub.par);
    EXPECT_EQ(msg_announce.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_announce.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_announce.id, pub.id);
    EXPECT_EQ(msg_announce.par, pub.par);

    enclave_dds_challenger_ctx_t sub_challenger = ENCLAVE_DDS_CHALLENGER_CTX_INIT;
    enclave_dds_challenge_t msg_challenge;
    enclave_dds_auth_on_announce(&sub_challenger, &sub, &msg_announce, &msg_challenge);
    EXPECT_EQ(msg_challenge.header.protocol, EDDS_RA_CHALLENGE);
    EXPECT_EQ(msg_challenge.header.peer_id, pub.id);
    EXPECT_EQ(msg_challenge.header.peer_par, pub.par);
    EXPECT_EQ(msg_challenge.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_challenge.header.length, ENCLAVE_DDS_HEADER_SIZE + sizeof(msg_challenge.body));
    EXPECT_EQ(msg_challenge.header.id, sub.id);
    EXPECT_EQ(msg_challenge.header.par, sub.par);

    enclave_dds_ra_response_t msg_response;
    enclave_dds_notify_t msg_notify;

    enclave_dds_auth_on_challenge(&pub, grp_key, &msg_challenge, &msg_response, &msg_notify);
    EXPECT_EQ(msg_response.header.protocol, EDDS_RA_RESPONSE);
    EXPECT_EQ(msg_response.header.peer_id, sub.id);
    EXPECT_EQ(msg_response.header.peer_par, sub.par);
    EXPECT_EQ(msg_response.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_response.header.length, ENCLAVE_DDS_RESPONSE_MSG_SIZE);
    EXPECT_EQ(msg_response.header.id, pub.id);
    EXPECT_EQ(msg_response.header.par, pub.par);

    EXPECT_EQ(msg_notify.header.protocol, EDDS_NOTIFY);
    EXPECT_EQ(msg_notify.header.peer_id, sub.id);
    EXPECT_EQ(msg_notify.header.peer_par, sub.par);
    EXPECT_EQ(msg_notify.header.payload_status, EDDS_PAYLOAD_AEAD);
    EXPECT_EQ(msg_notify.header.length, ENCLAVE_DDS_NOTIFY_MSG_SIZE);
    EXPECT_EQ(msg_notify.header.id, pub.id);
    EXPECT_EQ(msg_notify.header.par, pub.par);

    err = enclave_dds_auth_on_response(&sub_challenger, &msg_response,
        elf1_hash,
        (const uint8_t*)remote_root_pubkey, remote_root_pubkey_size);
    EXPECT_EQ(err, ERR_OK);

    enclave_endpoint_context_t sub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_dds_on_notify(&sub_challenger, &msg_notify, &sub_grp_ep);

    /* test if group key matches */
    uint8_t exported[ENCLAVE_DDS_GROUP_KEY_SIZE];
    crypto_aead_export(&sub_grp_ep.aead, exported);
    EXPECT_EQ(memcmp(exported, grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE), 0);

    /* send and recv message */
    vector<uint8_t> plaintext(128);
    std::iota(plaintext.begin(), plaintext.end(), 0);

    vector<uint8_t> msg(ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    size_t olen;
    err = enclave_dds_prepare_msg(&pub_grp_ep, &pub, plaintext.data(), plaintext.size(),
        (enclave_dds_msg_t *) msg.data(), msg.size(), &olen);
    EXPECT_EQ(olen, msg.size());
    EXPECT_EQ(err, ERR_OK);

    vector<uint8_t> recv(plaintext.size());
    err = enclave_dds_on_msg(&sub_grp_ep, (const enclave_dds_msg_t *) msg.data(), recv.data());
    EXPECT_EQ(err, ERR_OK);

    EXPECT_EQ(memcmp(plaintext.data(), recv.data(), plaintext.size()), 0);

    enclave_endpoint_free(&pub_grp_ep);
    enclave_endpoint_free(&sub_grp_ep);
}

TEST_F(EnclaveDDSProtocolTest, authenticatable_topic_memory_leak) {
    err_t err;

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    enclave_dds_participant_t pub = {.par = 1, .id = (int)elf1_load_id },
                              sub = {.par = 2, .id = 6};

    uint8_t grp_key[ENCLAVE_DDS_GROUP_KEY_SIZE];
    crypto_rng(grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE);

    enclave_endpoint_context_t pub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    enclave_endpoint_derive_from_key(&pub_grp_ep, grp_key);

    enclave_dds_join_t msg_join;
    enclave_dds_prepare_join(&sub, &msg_join);
    EXPECT_EQ(msg_join.protocol, EDDS_JOIN);
    EXPECT_EQ(msg_join.peer_id, ID_ANY);
    EXPECT_EQ(msg_join.peer_par, ID_ANY);
    EXPECT_EQ(msg_join.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_join.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_join.id, sub.id);
    EXPECT_EQ(msg_join.par, sub.par);

    enclave_dds_announce_t msg_announce;
    err = enclave_dds_on_join(&pub, &msg_join, &msg_announce);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(msg_announce.protocol, EDDS_ANNOUNCE);
    EXPECT_EQ(msg_announce.peer_id, sub.id);
    EXPECT_EQ(msg_announce.peer_par, sub.par);
    EXPECT_EQ(msg_announce.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_announce.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_announce.id, pub.id);
    EXPECT_EQ(msg_announce.par, pub.par);

    enclave_dds_challenger_ctx_t sub_challenger = ENCLAVE_DDS_CHALLENGER_CTX_INIT;
    enclave_dds_challenge_t msg_challenge;
    enclave_dds_auth_on_announce(&sub_challenger, &sub, &msg_announce, &msg_challenge);
    EXPECT_EQ(msg_challenge.header.protocol, EDDS_RA_CHALLENGE);
    EXPECT_EQ(msg_challenge.header.peer_id, pub.id);
    EXPECT_EQ(msg_challenge.header.peer_par, pub.par);
    EXPECT_EQ(msg_challenge.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_challenge.header.length, ENCLAVE_DDS_HEADER_SIZE + sizeof(msg_challenge.body));
    EXPECT_EQ(msg_challenge.header.id, sub.id);
    EXPECT_EQ(msg_challenge.header.par, sub.par);

    enclave_dds_ra_response_t msg_response;
    enclave_dds_notify_t msg_notify;

    enclave_dds_auth_on_challenge(&pub, grp_key, &msg_challenge, &msg_response, &msg_notify);
    EXPECT_EQ(msg_response.header.protocol, EDDS_RA_RESPONSE);
    EXPECT_EQ(msg_response.header.peer_id, sub.id);
    EXPECT_EQ(msg_response.header.peer_par, sub.par);
    EXPECT_EQ(msg_response.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_response.header.length, ENCLAVE_DDS_RESPONSE_MSG_SIZE);
    EXPECT_EQ(msg_response.header.id, pub.id);
    EXPECT_EQ(msg_response.header.par, pub.par);

    EXPECT_EQ(msg_notify.header.protocol, EDDS_NOTIFY);
    EXPECT_EQ(msg_notify.header.peer_id, sub.id);
    EXPECT_EQ(msg_notify.header.peer_par, sub.par);
    EXPECT_EQ(msg_notify.header.payload_status, EDDS_PAYLOAD_AEAD);
    EXPECT_EQ(msg_notify.header.length, ENCLAVE_DDS_NOTIFY_MSG_SIZE);
    EXPECT_EQ(msg_notify.header.id, pub.id);
    EXPECT_EQ(msg_notify.header.par, pub.par);

    err = enclave_dds_auth_on_response(&sub_challenger, &msg_response,
        elf1_hash,
        (const uint8_t*)remote_root_pubkey, remote_root_pubkey_size);
    EXPECT_EQ(err, ERR_OK);

    enclave_endpoint_context_t sub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_dds_on_notify(&sub_challenger, &msg_notify, &sub_grp_ep);

    /* test if group key matches */
    uint8_t exported[ENCLAVE_DDS_GROUP_KEY_SIZE];
    crypto_aead_export(&sub_grp_ep.aead, exported);
    EXPECT_EQ(memcmp(exported, grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE), 0);

    /* send and recv message */
    vector<uint8_t> plaintext(128);
    std::iota(plaintext.begin(), plaintext.end(), 0);

    vector<uint8_t> msg(ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    size_t olen;
    err = enclave_dds_prepare_msg(&pub_grp_ep, &pub, plaintext.data(), plaintext.size(),
        (enclave_dds_msg_t *) msg.data(), msg.size(), &olen);
    EXPECT_EQ(olen, msg.size());
    EXPECT_EQ(err, ERR_OK);

    vector<uint8_t> recv(plaintext.size());
    err = enclave_dds_on_msg(&sub_grp_ep, (const enclave_dds_msg_t *) msg.data(), recv.data());
    EXPECT_EQ(err, ERR_OK);

    EXPECT_EQ(memcmp(plaintext.data(), recv.data(), plaintext.size()), 0);

    enclave_endpoint_free(&pub_grp_ep);
    enclave_endpoint_free(&sub_grp_ep);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(EnclaveDDSProtocolTest, private_topic)
{
    err_t err;

    enclave_dds_participant_t pub = {.par = 1, .id = (int) elf1_load_id};
    enclave_dds_participant_t sub = {.par = 2, .id = (int) elf2_load_id};

    uint8_t grp_key[ENCLAVE_DDS_GROUP_KEY_SIZE];
    crypto_rng(grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE);

    enclave_endpoint_context_t pub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    enclave_endpoint_derive_from_key(&pub_grp_ep, grp_key);

    enclave_dds_join_t msg_join;
    enclave_dds_prepare_join(&sub, &msg_join);
    EXPECT_EQ(msg_join.protocol, EDDS_JOIN);
    EXPECT_EQ(msg_join.peer_id, ID_ANY);
    EXPECT_EQ(msg_join.peer_par, ID_ANY);
    EXPECT_EQ(msg_join.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_join.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_join.id, sub.id);
    EXPECT_EQ(msg_join.par, sub.par);

    enclave_dds_announce_t msg_announce;
    enclave_dds_on_join(&pub, &msg_join, &msg_announce);
    EXPECT_EQ(msg_announce.protocol, EDDS_ANNOUNCE);
    EXPECT_EQ(msg_announce.peer_id, sub.id);
    EXPECT_EQ(msg_announce.peer_par, sub.par);
    EXPECT_EQ(msg_announce.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_announce.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_announce.id, pub.id);
    EXPECT_EQ(msg_announce.par, pub.par);

    enclave_dds_ma_challenge_t msg_challenge;
    enclave_dds_challenger_ctx_t sub_challenger = ENCLAVE_DDS_CHALLENGER_CTX_INIT;

    enclave_dds_priv_on_announce(&sub_challenger, &sub, &msg_announce, &msg_challenge);
    EXPECT_EQ(msg_challenge.header.protocol, EDDS_MA_CHALLENGE);
    EXPECT_EQ(msg_challenge.header.peer_id, pub.id);
    EXPECT_EQ(msg_challenge.header.peer_par, pub.par);
    EXPECT_EQ(msg_challenge.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_challenge.header.length, ENCLAVE_DDS_MA_CHALLENGE_MSG_SIZE);
    EXPECT_EQ(msg_challenge.header.id, sub.id);
    EXPECT_EQ(msg_challenge.header.par, sub.par);

    enclave_dds_ma_challenge_response_t msg_challenge_response;
    enclave_dds_challenger_ctx_t pub_challenger = ENCLAVE_DDS_CHALLENGER_CTX_INIT;

    enclave_dds_priv_on_challenge(&pub_challenger, &pub, &msg_challenge, &msg_challenge_response);
    EXPECT_EQ(msg_challenge_response.header.protocol, EDDS_MA_CHALLENGE_RESPONSE);
    EXPECT_EQ(msg_challenge_response.header.peer_id, sub.id);
    EXPECT_EQ(msg_challenge_response.header.peer_par, sub.par);
    EXPECT_EQ(msg_challenge_response.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_challenge_response.header.length, ENCLAVE_DDS_MA_CHALLENGE_RESPONSE_MSG_SIZE);
    EXPECT_EQ(msg_challenge_response.header.id, pub.id);
    EXPECT_EQ(msg_challenge_response.header.par, pub.par);

    enclave_dds_response_t msg_response;
    err = enclave_dds_priv_on_challenge_response(&sub_challenger, &sub, &msg_challenge_response,
        elf1_hash, (const uint8_t *) remote_root_pubkey, remote_root_pubkey_size,
        &msg_response);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(msg_response.header.protocol, EDDS_MA_RESPONSE);
    EXPECT_EQ(msg_response.header.peer_id, pub.id);
    EXPECT_EQ(msg_response.header.peer_par, pub.par);
    EXPECT_EQ(msg_response.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_response.header.length, ENCLAVE_DDS_MA_RESPONSE_MSG_SIZE);
    EXPECT_EQ(msg_response.header.id, sub.id);
    EXPECT_EQ(msg_response.header.par, sub.par);

    enclave_dds_notify_t msg_notify;
    err = enclave_dds_priv_on_response(&pub_challenger, &pub,
        grp_key, elf2_hash, (const uint8_t *) remote_root_pubkey, remote_root_pubkey_size,
        &msg_response, &msg_notify);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(msg_notify.header.protocol, EDDS_NOTIFY);
    EXPECT_EQ(msg_notify.header.peer_id, sub.id);
    EXPECT_EQ(msg_notify.header.peer_par, sub.par);
    EXPECT_EQ(msg_notify.header.payload_status, EDDS_PAYLOAD_AEAD);
    EXPECT_EQ(msg_notify.header.length, ENCLAVE_DDS_NOTIFY_MSG_SIZE);
    EXPECT_EQ(msg_notify.header.id, pub.id);
    EXPECT_EQ(msg_notify.header.par, pub.par);

    enclave_endpoint_context_t sub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    err = enclave_dds_on_notify(&sub_challenger, &msg_notify, &sub_grp_ep);
    EXPECT_EQ(err, ERR_OK);

    vector<uint8_t> exported(ENCLAVE_DDS_GROUP_KEY_SIZE);
    crypto_aead_export(&sub_grp_ep.aead, exported.data());
    EXPECT_EQ(memcmp(grp_key, exported.data(), ENCLAVE_DDS_GROUP_KEY_SIZE), 0);

    vector<uint8_t> plaintext(128);
    iota(plaintext.begin(), plaintext.end(), 0);

    vector<uint8_t> msg(ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    size_t olen;
    err = enclave_dds_prepare_msg(&pub_grp_ep, &pub, plaintext.data(), plaintext.size(),
        (enclave_dds_msg_t *) msg.data(), msg.size(), &olen);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(olen, ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.protocol, EDDS_MSG);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.peer_id, ID_ANY);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.peer_par, ID_ANY);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.payload_status, EDDS_PAYLOAD_AEAD);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.length, ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.id, pub.id);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.par, pub.par);

    vector<uint8_t> recv(plaintext.size());
    err = enclave_dds_on_msg(&sub_grp_ep, (enclave_dds_msg_t *) msg.data(), recv.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(memcmp(plaintext.data(), recv.data(), plaintext.size()), 0);

    enclave_endpoint_free(&pub_grp_ep);
    enclave_endpoint_free(&sub_grp_ep);
}

TEST_F(EnclaveDDSProtocolTest, private_topic_memory_leak)
{
    err_t err;

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    enclave_dds_participant_t pub = {.par = 1, .id = (int) elf1_load_id};
    enclave_dds_participant_t sub = {.par = 2, .id = (int) elf2_load_id};

    uint8_t grp_key[ENCLAVE_DDS_GROUP_KEY_SIZE];
    crypto_rng(grp_key, ENCLAVE_DDS_GROUP_KEY_SIZE);

    enclave_endpoint_context_t pub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    enclave_endpoint_derive_from_key(&pub_grp_ep, grp_key);

    enclave_dds_join_t msg_join;
    enclave_dds_prepare_join(&sub, &msg_join);
    EXPECT_EQ(msg_join.protocol, EDDS_JOIN);
    EXPECT_EQ(msg_join.peer_id, ID_ANY);
    EXPECT_EQ(msg_join.peer_par, ID_ANY);
    EXPECT_EQ(msg_join.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_join.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_join.id, sub.id);
    EXPECT_EQ(msg_join.par, sub.par);

    enclave_dds_announce_t msg_announce;
    enclave_dds_on_join(&pub, &msg_join, &msg_announce);
    EXPECT_EQ(msg_announce.protocol, EDDS_ANNOUNCE);
    EXPECT_EQ(msg_announce.peer_id, sub.id);
    EXPECT_EQ(msg_announce.peer_par, sub.par);
    EXPECT_EQ(msg_announce.payload_status, EDDS_PAYLOAD_EMPTY);
    EXPECT_EQ(msg_announce.length, ENCLAVE_DDS_HEADER_SIZE);
    EXPECT_EQ(msg_announce.id, pub.id);
    EXPECT_EQ(msg_announce.par, pub.par);

    enclave_dds_ma_challenge_t msg_challenge;
    enclave_dds_challenger_ctx_t sub_challenger = ENCLAVE_DDS_CHALLENGER_CTX_INIT;

    enclave_dds_priv_on_announce(&sub_challenger, &sub, &msg_announce, &msg_challenge);
    EXPECT_EQ(msg_challenge.header.protocol, EDDS_MA_CHALLENGE);
    EXPECT_EQ(msg_challenge.header.peer_id, pub.id);
    EXPECT_EQ(msg_challenge.header.peer_par, pub.par);
    EXPECT_EQ(msg_challenge.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_challenge.header.length, ENCLAVE_DDS_MA_CHALLENGE_MSG_SIZE);
    EXPECT_EQ(msg_challenge.header.id, sub.id);
    EXPECT_EQ(msg_challenge.header.par, sub.par);

    enclave_dds_ma_challenge_response_t msg_challenge_response;
    enclave_dds_challenger_ctx_t pub_challenger = ENCLAVE_DDS_CHALLENGER_CTX_INIT;

    enclave_dds_priv_on_challenge(&pub_challenger, &pub, &msg_challenge, &msg_challenge_response);
    EXPECT_EQ(msg_challenge_response.header.protocol, EDDS_MA_CHALLENGE_RESPONSE);
    EXPECT_EQ(msg_challenge_response.header.peer_id, sub.id);
    EXPECT_EQ(msg_challenge_response.header.peer_par, sub.par);
    EXPECT_EQ(msg_challenge_response.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_challenge_response.header.length, ENCLAVE_DDS_MA_CHALLENGE_RESPONSE_MSG_SIZE);
    EXPECT_EQ(msg_challenge_response.header.id, pub.id);
    EXPECT_EQ(msg_challenge_response.header.par, pub.par);

    enclave_dds_response_t msg_response;
    err = enclave_dds_priv_on_challenge_response(&sub_challenger, &sub, &msg_challenge_response,
        elf1_hash, (const uint8_t *) remote_root_pubkey, remote_root_pubkey_size,
        &msg_response);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(msg_response.header.protocol, EDDS_MA_RESPONSE);
    EXPECT_EQ(msg_response.header.peer_id, pub.id);
    EXPECT_EQ(msg_response.header.peer_par, pub.par);
    EXPECT_EQ(msg_response.header.payload_status, EDDS_PAYLOAD_PLAINTEXT);
    EXPECT_EQ(msg_response.header.length, ENCLAVE_DDS_MA_RESPONSE_MSG_SIZE);
    EXPECT_EQ(msg_response.header.id, sub.id);
    EXPECT_EQ(msg_response.header.par, sub.par);

    enclave_dds_notify_t msg_notify;
    err = enclave_dds_priv_on_response(&pub_challenger, &pub,
        grp_key, elf2_hash, (const uint8_t *) remote_root_pubkey, remote_root_pubkey_size,
        &msg_response, &msg_notify);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(msg_notify.header.protocol, EDDS_NOTIFY);
    EXPECT_EQ(msg_notify.header.peer_id, sub.id);
    EXPECT_EQ(msg_notify.header.peer_par, sub.par);
    EXPECT_EQ(msg_notify.header.payload_status, EDDS_PAYLOAD_AEAD);
    EXPECT_EQ(msg_notify.header.length, ENCLAVE_DDS_NOTIFY_MSG_SIZE);
    EXPECT_EQ(msg_notify.header.id, pub.id);
    EXPECT_EQ(msg_notify.header.par, pub.par);

    enclave_endpoint_context_t sub_grp_ep = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    err = enclave_dds_on_notify(&sub_challenger, &msg_notify, &sub_grp_ep);
    EXPECT_EQ(err, ERR_OK);

    vector<uint8_t> exported(ENCLAVE_DDS_GROUP_KEY_SIZE);
    crypto_aead_export(&sub_grp_ep.aead, exported.data());
    EXPECT_EQ(memcmp(grp_key, exported.data(), ENCLAVE_DDS_GROUP_KEY_SIZE), 0);

    vector<uint8_t> plaintext(128);
    iota(plaintext.begin(), plaintext.end(), 0);

    vector<uint8_t> msg(ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    size_t olen;
    err = enclave_dds_prepare_msg(&pub_grp_ep, &pub, plaintext.data(), plaintext.size(),
        (enclave_dds_msg_t *) msg.data(), msg.size(), &olen);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(olen, ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.protocol, EDDS_MSG);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.peer_id, ID_ANY);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.peer_par, ID_ANY);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.payload_status, EDDS_PAYLOAD_AEAD);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.length, ENCLAVE_DDS_MSG_SIZE_FROM_PLAINTEXT(plaintext.size()));
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.id, pub.id);
    EXPECT_EQ(((enclave_dds_msg_t *) msg.data())->header.par, pub.par);

    vector<uint8_t> recv(plaintext.size());
    err = enclave_dds_on_msg(&sub_grp_ep, (enclave_dds_msg_t *) msg.data(), recv.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(memcmp(plaintext.data(), recv.data(), plaintext.size()), 0);

    enclave_endpoint_free(&pub_grp_ep);
    enclave_endpoint_free(&sub_grp_ep);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}
