#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <numeric>
#include <vector>
using namespace std;

#include "common.h"
#include <enclave_common.h>

class EnclavePlatformAttestationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static bool init = false;
        if (init)
            return;
        crypto_init();
        enclave_platform_init();
        init = true;
    }
    void TearDown() override
    {
    }
};

static const char remote_root_pubkey[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEH6ZLw2s0NqHtnzP83vVdd6sInMk20M0I\n"
    "kZxSA91uBTwrP8FD505M/HDHaJ2tsxQySd+9x/4qlNQCiOpDUb3eTg==\n"
    "-----END PUBLIC KEY-----\0";

static const size_t remote_root_pubkey_len = sizeof(remote_root_pubkey);

static vector<vector<uint8_t>> elf_file =
    {
        {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,},
        {0x03, 0x12, 0x25, 0x18}
    };

static vector<vector<uint8_t>> elf_file2 =
    {
        {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,},
        {0x03, 0x12, 0x25, 0x18},
        {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,},
        {0x03, 0x12, 0x25, 0x18}
    };

TEST_F(EnclavePlatformAttestationTest, report)
{
    enclave_node_t * node = enclave_node_create(0);
    enclave_node_load_start(node);
    for (auto & chunk : elf_file)
    {
        enclave_node_load_chunk(node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&node->loader, node->hash);
    puthex_n(node->hash, CRYPTO_HASH_SIZE);

    vector<uint8_t> hash(CRYPTO_HASH_SIZE);
    memcpy(hash.data(), node->hash, CRYPTO_HASH_SIZE);

    // in enclave user
    crypto_dh_context_t dh = CRYPTO_DH_CONTEXT_INIT;
    vector<uint8_t> pubkey(CRYPTO_DH_PUBKEY_SIZE);
    crypto_dh_propose(&dh, pubkey.data());
    puthex(pubkey);

    // in local attestation supervisor
    vector<uint8_t> report(ENCLAVE_NODE_REPORT_SIZE);
    vector<uint8_t> nonce(ENCLAVE_ATTESTATION_NONCE_SIZE);
    std::iota(nonce.begin(), nonce.end(), 0);
    enclave_node_report(node, nonce.data(), pubkey.data(), (enclave_node_report_t *) report.data());
    puthex(report);

    // in remote attestation server
    err_t err = enclave_report_verify(
        (const enclave_node_report_t *) report.data(),
        nonce.data(),
        hash.data(),
        (const uint8_t*) remote_root_pubkey, remote_root_pubkey_len);
    EXPECT_EQ(err, ERR_OK);
}

TEST_F(EnclavePlatformAttestationTest, remote_attestation)
{
    // enclave client
    vector<uint8_t> remote_binary(CRYPTO_HASH_SIZE);
    enclave_endpoint_context_t client = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    vector<uint8_t> msg1(ENCLAVE_ATTESTATION_CHALLENGE_SIZE);

    enclave_attestation_context_t ctx = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    enclave_ra_challenge(&ctx, (enclave_attestation_challenge_t *) msg1.data());
    puthex(msg1);

    // remote attestation server
    enclave_node_t * node = enclave_node_create(0);
    enclave_node_load_start(node);
    for (auto & chunk : elf_file)
    {
        enclave_node_load_chunk(node, chunk.data(), chunk.size());
    }

    enclave_endpoint_context_t server = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    vector<uint8_t> msg2(ENCLAVE_NODE_REPORT_SIZE);
    crypto_hash_report(&node->loader, node->hash);

    // client already know
    remote_binary.assign(node->hash, node->hash + CRYPTO_HASH_SIZE);
    //

    enclave_ra_response(node->node_id,
        (const enclave_attestation_challenge_t *) msg1.data(),
        (enclave_node_report_t *) msg2.data(),
        &server);
    puthex(msg2);

    // enclave client
    err_t err;
    err = enclave_ra_verify(&ctx,
        remote_binary.data(),
        (const uint8_t *) remote_root_pubkey, remote_root_pubkey_len,
        (const enclave_node_report_t *) msg2.data());
    EXPECT_EQ(err, ERR_OK);
    enclave_endpoint_derive_from_attestation(&ctx, &client);

    // enclave server
    string secrete = "Hello!";
    vector<uint8_t> aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
    ((size_t *) aad.data())[0] = 0;
    ((size_t *) aad.data())[1] = 1;
    crypto_aead_encrypt(&server.aead, aad.data(), aad.size(),
        (const uint8_t *) secrete.data(), secrete.size(),
        ciphertext.data(), nonce.data());
    puthex(ciphertext);

    // enclave client
    vector<uint8_t> plaintext(CRYPTO_AEAD_PLAINTEXT_SIZE(ciphertext.size()));
    err = crypto_aead_decrypt(&client.aead, aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        nonce.data(), plaintext.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), secrete.size());
    puthex(plaintext);

    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));

    string plaintext_str(plaintext.begin(), plaintext.end());
    std::cout << plaintext_str << std::endl;
}

TEST_F(EnclavePlatformAttestationTest, remote_attestation_memory_leak)
{

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    // enclave client
    vector<uint8_t> remote_binary(CRYPTO_HASH_SIZE);
    enclave_endpoint_context_t client = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    vector<uint8_t> msg1(ENCLAVE_ATTESTATION_CHALLENGE_SIZE);

    enclave_attestation_context_t ctx = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    enclave_ra_challenge(&ctx, (enclave_attestation_challenge_t *) msg1.data());
    puthex(msg1);

    // remote attestation server
    enclave_node_t * node = enclave_node_create(0);
    enclave_node_load_start(node);
    for (auto & chunk : elf_file)
    {
        enclave_node_load_chunk(node, chunk.data(), chunk.size());
    }

    enclave_endpoint_context_t server = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    vector<uint8_t> msg2(ENCLAVE_NODE_REPORT_SIZE);
    crypto_hash_report(&node->loader, node->hash);

    // client already know
    remote_binary.assign(node->hash, node->hash + CRYPTO_HASH_SIZE);
    //

    enclave_ra_response(node->node_id,
        (const enclave_attestation_challenge_t *) msg1.data(),
        (enclave_node_report_t *) msg2.data(),
        &server);
    puthex(msg2);

    // enclave client
    err_t err;
    err = enclave_ra_verify(&ctx,
        remote_binary.data(),
        (const uint8_t *) remote_root_pubkey, remote_root_pubkey_len,
        (const enclave_node_report_t *) msg2.data());
    EXPECT_EQ(err, ERR_OK);
    enclave_endpoint_derive_from_attestation(&ctx, &client);

    // enclave server
    string secrete = "Hello!";
    vector<uint8_t> aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
    ((size_t *) aad.data())[0] = 0;
    ((size_t *) aad.data())[1] = 1;
    crypto_aead_encrypt(&server.aead, aad.data(), aad.size(),
        (const uint8_t *) secrete.data(), secrete.size(),
        ciphertext.data(), nonce.data());
    puthex(ciphertext);

    // enclave client
    vector<uint8_t> plaintext(CRYPTO_AEAD_PLAINTEXT_SIZE(ciphertext.size()));
    err = crypto_aead_decrypt(&client.aead, aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        nonce.data(), plaintext.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), secrete.size());
    puthex(plaintext);

    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));

    string plaintext_str(plaintext.begin(), plaintext.end());
    std::cout << plaintext_str << std::endl;

    crypto_aead_free(&client.aead);
    crypto_aead_free(&server.aead);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(EnclavePlatformAttestationTest, mutual_attestation)
{
    err_t err;

    enclave_attestation_context_t
        initiator = ENCLAVE_ATTESTATION_CONTEXT_INIT,
        responder = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    vector<uint8_t> initiator_binary(CRYPTO_HASH_SIZE), responder_binary(CRYPTO_HASH_SIZE);
    vector<uint8_t>
        msg1(ENCLAVE_ATTESTATION_CHALLENGE_SIZE),
        msg2(ENCLAVE_NODE_REPORT_SIZE),
        msg3(ENCLAVE_NODE_REPORT_SIZE);

    enclave_node_t * initiator_node = enclave_node_create(0);
    enclave_node_t * responder_node = enclave_node_create(1);

    // secure loader
    enclave_node_load_start(initiator_node);
    for (auto & chunk : elf_file)
    {
        enclave_node_load_chunk(initiator_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&initiator_node->loader, initiator_node->hash);
    initiator_binary.assign(initiator_node->hash, initiator_node->hash + CRYPTO_HASH_SIZE);

    enclave_node_load_start(responder_node);
    for (auto & chunk : elf_file2)
    {
        enclave_node_load_chunk(responder_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&responder_node->loader, responder_node->hash);
    responder_binary.assign(responder_node->hash, responder_node->hash + CRYPTO_HASH_SIZE);


    // initiator
    enclave_ma_initiator_challenge(&initiator, (enclave_attestation_challenge_t *) msg1.data());
    puthex(msg1);

    // responder
    enclave_ma_responder_response(&responder,
        responder_node->node_id,
        (const enclave_attestation_challenge_t *) msg1.data(),
        (enclave_node_report_t *) msg2.data());
    puthex(msg2);

    // initiator
    err = enclave_ma_initiator_response(&initiator,
        initiator_node->node_id,
        responder_binary.data(),
        (const uint8_t *) remote_root_pubkey, remote_root_pubkey_len,
        (const enclave_node_report_t *) msg2.data(),
        (enclave_node_report_t *) msg3.data());
    puthex(msg3);
    ASSERT_EQ(err, ERR_OK);

    // responder
    err = enclave_ma_responder_verify(&responder,
        initiator_binary.data(),
        (const uint8_t *) remote_root_pubkey, remote_root_pubkey_len,
        (const enclave_node_report_t *) msg3.data());
    ASSERT_EQ(err, ERR_OK);

    // initiator
    enclave_endpoint_context_t
        initiator_endpoint = ENCLAVE_ENDPOINT_CONTEXT_INIT,
        responder_endpoint = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_endpoint_derive_from_attestation(&initiator, &initiator_endpoint);
    enclave_endpoint_derive_from_attestation(&responder, &responder_endpoint);

    string secrete = "Hello!";
    vector<uint8_t>
        aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
    ((size_t *) aad.data())[0] = 0;
    ((size_t *) aad.data())[1] = 1;

    crypto_aead_encrypt(&initiator_endpoint.aead, aad.data(), aad.size(),
        (const uint8_t *) secrete.data(), secrete.size(),
        ciphertext.data(), nonce.data());
    puthex(ciphertext);

    vector<uint8_t> plaintext(CRYPTO_AEAD_PLAINTEXT_SIZE(ciphertext.size()));
    err = crypto_aead_decrypt(&responder_endpoint.aead, aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        nonce.data(), plaintext.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), secrete.size());
    puthex(plaintext);

    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));

    string plaintext_str(plaintext.begin(), plaintext.end());
    std::cout << plaintext_str << std::endl;

    crypto_aead_free(&initiator_endpoint.aead);
    crypto_aead_free(&responder_endpoint.aead);
}

TEST_F(EnclavePlatformAttestationTest, mutual_attestation_memory_leak)
{
    err_t err;
#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    enclave_attestation_context_t
        initiator = ENCLAVE_ATTESTATION_CONTEXT_INIT,
        responder = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    vector<uint8_t> initiator_binary(CRYPTO_HASH_SIZE), responder_binary(CRYPTO_HASH_SIZE);
    vector<uint8_t>
        msg1(ENCLAVE_ATTESTATION_CHALLENGE_SIZE),
        msg2(ENCLAVE_NODE_REPORT_SIZE),
        msg3(ENCLAVE_NODE_REPORT_SIZE);

    enclave_node_t * initiator_node = enclave_node_create(0);
    enclave_node_t * responder_node = enclave_node_create(1);

    // secure loader
    enclave_node_load_start(initiator_node);
    for (auto & chunk : elf_file)
    {
        enclave_node_load_chunk(initiator_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&initiator_node->loader, initiator_node->hash);
    initiator_binary.assign(initiator_node->hash, initiator_node->hash + CRYPTO_HASH_SIZE);

    enclave_node_load_start(responder_node);
    for (auto & chunk : elf_file2)
    {
        enclave_node_load_chunk(responder_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&responder_node->loader, responder_node->hash);
    responder_binary.assign(responder_node->hash, responder_node->hash + CRYPTO_HASH_SIZE);


    // initiator
    enclave_ma_initiator_challenge(&initiator, (enclave_attestation_challenge_t *) msg1.data());

    // responder
    enclave_ma_responder_response(&responder,
        responder_node->node_id,
        (const enclave_attestation_challenge_t *) msg1.data(),
        (enclave_node_report_t *) msg2.data());

    // initiator
    err = enclave_ma_initiator_response(&initiator,
        initiator_node->node_id,
        responder_binary.data(),
        (const uint8_t *) remote_root_pubkey, remote_root_pubkey_len,
        (const enclave_node_report_t *) msg2.data(),
        (enclave_node_report_t *) msg3.data());
    ASSERT_EQ(err, ERR_OK);

    // responder
    err = enclave_ma_responder_verify(&responder,
        initiator_binary.data(),
        (const uint8_t *) remote_root_pubkey, remote_root_pubkey_len,
        (const enclave_node_report_t *) msg3.data());
    ASSERT_EQ(err, ERR_OK);

    // initiator
    enclave_endpoint_context_t
        initiator_endpoint = ENCLAVE_ENDPOINT_CONTEXT_INIT,
        responder_endpoint = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_endpoint_derive_from_attestation(&initiator, &initiator_endpoint);
    enclave_endpoint_derive_from_attestation(&responder, &responder_endpoint);

    string secrete = "Hello!";
    vector<uint8_t>
        aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
    ((size_t *) aad.data())[0] = 0;
    ((size_t *) aad.data())[1] = 1;

    crypto_aead_encrypt(&initiator_endpoint.aead, aad.data(), aad.size(),
        (const uint8_t *) secrete.data(), secrete.size(),
        ciphertext.data(), nonce.data());

    vector<uint8_t> plaintext(CRYPTO_AEAD_PLAINTEXT_SIZE(ciphertext.size()));
    err = crypto_aead_decrypt(&responder_endpoint.aead, aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        nonce.data(), plaintext.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), secrete.size());

    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));

    crypto_aead_free(&initiator_endpoint.aead);
    crypto_aead_free(&responder_endpoint.aead);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(EnclavePlatformAttestationTest, local_attestation)
{
    err_t                         err;
    enclave_attestation_context_t initiator = ENCLAVE_ATTESTATION_CONTEXT_INIT,
                                  responder = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    vector<uint8_t> initiator_binary(CRYPTO_HASH_SIZE),
        responder_binary(CRYPTO_HASH_SIZE);
    vector<uint8_t> msg1(ENCLAVE_ATTESTATION_CHALLENGE_SIZE),
        msg2(ENCLAVE_NODE_REPORT_SIZE), msg3(ENCLAVE_NODE_REPORT_SIZE);

    enclave_node_t* initiator_node = enclave_node_create(0);
    enclave_node_t* responder_node = enclave_node_create(1);

    // secure loader
    enclave_node_load_start(initiator_node);
    for (auto& chunk : elf_file)
    {
        enclave_node_load_chunk(initiator_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&initiator_node->loader, initiator_node->hash);
    initiator_binary.assign(
        initiator_node->hash, initiator_node->hash + CRYPTO_HASH_SIZE);

    enclave_node_load_start(responder_node);
    for (auto& chunk : elf_file2)
    {
        enclave_node_load_chunk(responder_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&responder_node->loader, responder_node->hash);
    responder_binary.assign(
        responder_node->hash, responder_node->hash + CRYPTO_HASH_SIZE);

    // initiator
    enclave_la_initiator_challenge(
        &initiator, (enclave_attestation_challenge_t*)msg1.data());
    puthex(msg1);

    // responder
    enclave_la_responder_response(&responder, responder_node->node_id,
        (const enclave_attestation_challenge_t*)msg1.data(),
        (enclave_node_report_t*)msg2.data());
    puthex(msg2);

    // initiator
    err = enclave_la_initiator_response(&initiator, initiator_node->node_id,
        responder_binary.data(), (const enclave_node_report_t*)msg2.data(),
        (enclave_node_report_t*)msg3.data());
    ASSERT_EQ(err, ERR_OK);
    puthex(msg3);

    // responder
    err = enclave_la_responder_verify(&responder, initiator_binary.data(),
        (const enclave_node_report_t*)msg3.data());
    ASSERT_EQ(err, ERR_OK);

    // initiator
    enclave_endpoint_context_t initiator_endpoint
        = ENCLAVE_ENDPOINT_CONTEXT_INIT,
        responder_endpoint = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_endpoint_derive_from_attestation(&initiator, &initiator_endpoint);
    enclave_endpoint_derive_from_attestation(&responder, &responder_endpoint);

    string          secrete = "Hello!";
    vector<uint8_t> aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
    ((size_t*)aad.data())[0] = 0;
    ((size_t*)aad.data())[1] = 1;

    crypto_aead_encrypt(&initiator_endpoint.aead, aad.data(), aad.size(),
        (const uint8_t*)secrete.data(), secrete.size(), ciphertext.data(),
        nonce.data());

    vector<uint8_t> plaintext(CRYPTO_AEAD_PLAINTEXT_SIZE(ciphertext.size()));
    err = crypto_aead_decrypt(&responder_endpoint.aead, aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(), nonce.data(), plaintext.data());

    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), secrete.size());

    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));

    crypto_aead_free(&initiator_endpoint.aead);
    crypto_aead_free(&responder_endpoint.aead);
}

TEST_F(EnclavePlatformAttestationTest, local_attestation_memory_leak)
{
    err_t err;
#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    enclave_attestation_context_t initiator = ENCLAVE_ATTESTATION_CONTEXT_INIT,
                                  responder = ENCLAVE_ATTESTATION_CONTEXT_INIT;
    vector<uint8_t> initiator_binary(CRYPTO_HASH_SIZE),
        responder_binary(CRYPTO_HASH_SIZE);
    vector<uint8_t> msg1(ENCLAVE_ATTESTATION_CHALLENGE_SIZE),
        msg2(ENCLAVE_NODE_REPORT_SIZE), msg3(ENCLAVE_NODE_REPORT_SIZE);

    enclave_node_t* initiator_node = enclave_node_create(0);
    enclave_node_t* responder_node = enclave_node_create(1);

    // secure loader
    enclave_node_load_start(initiator_node);
    for (auto& chunk : elf_file)
    {
        enclave_node_load_chunk(initiator_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&initiator_node->loader, initiator_node->hash);
    initiator_binary.assign(
        initiator_node->hash, initiator_node->hash + CRYPTO_HASH_SIZE);

    enclave_node_load_start(responder_node);
    for (auto& chunk : elf_file2)
    {
        enclave_node_load_chunk(responder_node, chunk.data(), chunk.size());
    }
    crypto_hash_report(&responder_node->loader, responder_node->hash);
    responder_binary.assign(
        responder_node->hash, responder_node->hash + CRYPTO_HASH_SIZE);

    // initiator
    enclave_la_initiator_challenge(
        &initiator, (enclave_attestation_challenge_t*)msg1.data());

    // responder
    enclave_la_responder_response(&responder, responder_node->node_id,
        (const enclave_attestation_challenge_t*)msg1.data(),
        (enclave_node_report_t*)msg2.data());

    // initiator
    err = enclave_la_initiator_response(&initiator, initiator_node->node_id,
        responder_binary.data(), (const enclave_node_report_t*)msg2.data(),
        (enclave_node_report_t*)msg3.data());
    ASSERT_EQ(err, ERR_OK);

    // responder
    err = enclave_la_responder_verify(&responder, initiator_binary.data(),
        (const enclave_node_report_t*)msg3.data());
    ASSERT_EQ(err, ERR_OK);

    // initiator
    enclave_endpoint_context_t initiator_endpoint
        = ENCLAVE_ENDPOINT_CONTEXT_INIT,
        responder_endpoint = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_endpoint_derive_from_attestation(&initiator, &initiator_endpoint);
    enclave_endpoint_derive_from_attestation(&responder, &responder_endpoint);

    string          secrete = "Hello!";
    vector<uint8_t> aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
    ((size_t*)aad.data())[0] = 0;
    ((size_t*)aad.data())[1] = 1;

    crypto_aead_encrypt(&initiator_endpoint.aead, aad.data(), aad.size(),
        (const uint8_t*)secrete.data(), secrete.size(), ciphertext.data(),
        nonce.data());

    vector<uint8_t> plaintext(CRYPTO_AEAD_PLAINTEXT_SIZE(ciphertext.size()));
    err = crypto_aead_decrypt(&responder_endpoint.aead, aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(), nonce.data(), plaintext.data());

    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), secrete.size());

    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));

    crypto_aead_free(&initiator_endpoint.aead);
    crypto_aead_free(&responder_endpoint.aead);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(EnclavePlatformAttestationTest, endpoint_seal)
{

    uint8_t key[CRYPTO_AEAD_KEY_SIZE];
    crypto_rng(key, sizeof(key));

    enclave_endpoint_context_t a = ENCLAVE_ENDPOINT_CONTEXT_INIT,
        b = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_endpoint_init(&a, 3, 2);
    enclave_endpoint_init(&b, 6, 3);

    enclave_endpoint_derive_from_key(&a, key);
    enclave_endpoint_derive_from_key(&b, key);

    err_t err;
    size_t k = 100;
    vector<uint8_t> data(1024), plaintext(1024), message(ENCLAVE_MESSAGE_SIZE(data.size()));
    std::iota(data.begin(), data.end(), 0);

    enclave_endpoint_seal(&a, data.data(), data.size(), (enclave_message_t *) message.data());
    enclave_message_t * msg = (enclave_message_t *) message.data();
    std::printf("seq = %u, par = %u, id = %u, size = %u\n",
        msg->header.sequence, msg->header.node_par, msg->header.node_id,
        msg->header.size);
    puthex_n(message.data(), 128);

    std::fill(plaintext.begin(), plaintext.end(), 0);
    err = enclave_endpoint_unseal(&b, (const enclave_message_t *) message.data(), plaintext.data());
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), data.size());
    EXPECT_EQ(0, memcmp(plaintext.data(), data.data(), data.size()));

    while (k -- > 0)
    {
        enclave_endpoint_seal(&a, data.data(), data.size(), (enclave_message_t *) message.data());
        std::fill(plaintext.begin(), plaintext.end(), 0);
        err = enclave_endpoint_unseal(&b, (const enclave_message_t *) message.data(), plaintext.data());
        EXPECT_EQ(err, ERR_OK);
        EXPECT_EQ(plaintext.size(), data.size());
        EXPECT_EQ(0, memcmp(plaintext.data(), data.data(), data.size()));
    }

}

TEST_F(EnclavePlatformAttestationTest, endpoint_seal_memory_leak)
{

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    uint8_t key[CRYPTO_AEAD_KEY_SIZE];
    crypto_rng(key, sizeof(key));

    enclave_endpoint_context_t a = ENCLAVE_ENDPOINT_CONTEXT_INIT,
        b = ENCLAVE_ENDPOINT_CONTEXT_INIT;

    enclave_endpoint_init(&a, 3, 2);
    enclave_endpoint_init(&b, 6, 3);

    enclave_endpoint_derive_from_key(&a, key);
    enclave_endpoint_derive_from_key(&b, key);

    vector<uint8_t> data(1024), plaintext(1024), message(ENCLAVE_MESSAGE_SIZE(data.size()));
    std::iota(data.begin(), data.end(), 0);
    std::fill(plaintext.begin(), plaintext.end(), 0);

    err_t err;
    enclave_endpoint_seal(&a, data.data(), data.size(), (enclave_message_t *) message.data());
    err = enclave_endpoint_unseal(&b, (const enclave_message_t *) message.data(), plaintext.data());

    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(plaintext.size(), data.size());
    EXPECT_EQ(0, memcmp(plaintext.data(), data.data(), data.size()));

    enclave_endpoint_free(&a);
    enclave_endpoint_free(&b);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}
