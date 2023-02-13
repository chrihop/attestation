#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <numeric>
#include <vector>
using namespace std;

#include <enclave_platform.h>

void _puthex(const char * name, const vector<unsigned char> & data)
{
    std::printf("%s (size %zu): ", name, data.size());
    for (int i = 0; i < data.size(); i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

void _puthex_n(const char * name, const vector<unsigned char> & data, size_t n)
{
    size_t k = std::min(n, data.size());
    std::printf("%s (size %zu): ", name, k);
    for (int i = 0; i < k; i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

void _puthex_n(const char * name, const void * data, size_t n)
{
    std::printf("%s (size %zu): ", name, n);
    for (int i = 0; i < n; i++)
    {
        std::printf("%02x", ((uint8_t *)data)[i]);
    }
    std::printf("\n");
}

#define puthex(var) _puthex(#var, var)
#define puthex_n(var, n) _puthex_n(#var, var, n)

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
