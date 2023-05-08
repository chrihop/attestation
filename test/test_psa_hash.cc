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

TEST_F(PsaSecureHash, sha256_multiple)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    vector<uint8_t> data(512);
    iota(data.begin(), data.end(), 0);

    psa_status_t status;
    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_update(&op, data.data(), data.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> hash_one(32), hash_multiple(32);
    size_t olen = 0;
    status = psa_hash_finish(&op, hash_one.data(), hash_one.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_abort(&op);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_update(&op, data.data(), data.size() / 2);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_update(&op, data.data() + data.size() / 2, data.size() / 2);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_finish(&op, hash_multiple.data(), hash_multiple.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_hash_abort(&op);
    ASSERT_EQ(status, PSA_SUCCESS);

    puthex(hash_one);
    puthex(hash_multiple);

    ASSERT_EQ(hash_one, hash_multiple);
}

TEST_F(PsaSecureHash, hmac_sha265)
{
    psa_status_t status;
    uint8_t hmac_key[32];
    iota(hmac_key, hmac_key + sizeof(hmac_key), 0);

    psa_key_id_t key;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

    status = psa_import_key(&attr, hmac_key, sizeof(hmac_key), &key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> data(512);
    iota(data.begin(), data.end(), 0);

    vector<uint8_t> hash(32);
    size_t olen;

    status = psa_mac_compute(key,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        data.data(),
        data.size(), hash.data(), hash.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);

    puthex(hash);

    status = psa_mac_verify(key,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        data.data(),
        data.size(), hash.data(), hash.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_mac_compute(key,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        data.data(),
        data.size(), hash.data(), hash.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);

    puthex(hash);

    status = psa_mac_verify(key,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        data.data(),
        data.size(), hash.data(), hash.size());
    ASSERT_EQ(status, PSA_SUCCESS);

}
