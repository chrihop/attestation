#include <gtest/gtest.h>
#include <psa/crypto.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <abstraction.h>
#include <vector>
#include <numeric>
using namespace std;

class PsaSecureHash : public ::testing::Test {
public:
    void SetUp() override
    {
        crypto_init();
    }

    void TearDown() override
    {
        mbedtls_psa_crypto_free();
    }
};

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
    std::printf("%s (size %zu B): ", name, k);
    for (int i = 0; i < k; i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

#define puthex(var) _puthex(#var, var)
#define puthex_n(var, n) _puthex_n(#var, var, n)

TEST_F(PsaSecureHash, sha256)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    std::printf("operation size: %zu\n", sizeof(op));
    psa_status_t status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    ASSERT_EQ(status, PSA_SUCCESS);

    const char * msg = "The quick brown fox jumps over the lazy dog";
    status = psa_hash_update(&op, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> hash(32);
    size_t hash_length = 0;
    status = psa_hash_finish(&op, hash.data(), hash.size(), &hash_length);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_EQ(hash_length, 32);
    puthex(hash);

    status = psa_hash_abort(&op);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_update(&op, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_hash_verify(&op, hash.data(), hash.size());
    ASSERT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaSecureHash, sha256_memory_leak)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    std::printf("operation size: %zu\n", sizeof(op));
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);

    psa_status_t status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    ASSERT_EQ(status, PSA_SUCCESS);

    const char * msg = "The quick brown fox jumps over the lazy dog";
    status = psa_hash_update(&op, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> hash(32);
    size_t hash_length = 0;
    status = psa_hash_finish(&op, hash.data(), hash.size(), &hash_length);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_EQ(hash_length, 32);
    puthex(hash);

    status = psa_hash_abort(&op);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_update(&op, (const uint8_t *)msg, strlen(msg));
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_hash_verify(&op, hash.data(), hash.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
}
