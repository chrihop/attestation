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
#include <enclave_platform.h>

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
    enclave_node_report(node, pubkey.data(), (enclave_node_report_t *) report.data());
    puthex(report);

    // in remote attestation server
    err_t err = enclave_report_verify(
        (const enclave_node_report_t *) report.data(),
        hash.data(),
        (const uint8_t*) remote_root_pubkey, remote_root_pubkey_len);
    EXPECT_EQ(err, ERR_OK);
}

TEST_F(EnclavePlatformAttestationTest, remote_attestation)
{
    // enclave client
    vector<uint8_t> remote_binary(CRYPTO_HASH_SIZE);
    enclave_endpoint_context_t client = ENCLAVE_ENDPOINT_CONTEXT_INIT;
    vector<uint8_t> msg1(ENCLAVE_REMOTE_ATTESTATION_CHALLENGE_SIZE);

    enclave_remote_attestation_context_t ctx = ENCLAVE_REMOTE_ATTESTATION_CONTEXT_INIT;
    enclave_ra_challenge(&ctx, (enclave_remote_attestation_challenge_t *) msg1.data());
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
        (const enclave_remote_attestation_challenge_t *) msg1.data(),
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
    enclave_ra_derive_endpoint(&ctx, &client);

    // enclave server
    string secrete = "Hello!";
    vector<uint8_t> aad(16), nonce(CRYPTO_AEAD_NONCE_SIZE),
        ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(secrete.size()));
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
    EXPECT_EQ(0, memcmp(plaintext.data(), secrete.data(), secrete.size()));
    puthex(plaintext);

    string plaintext_str((char *) plaintext.data(), plaintext.size() + 1);
    std::cout << plaintext_str << std::endl;
}
