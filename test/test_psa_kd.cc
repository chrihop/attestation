#include <gtest/gtest.h>
#include <psa/crypto.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <abstraction.h>
#include <vector>
#include <numeric>
using namespace std;

class PsaKDFunction : public ::testing::Test {
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
    std::printf("%s (size %zu): ", name, k);
    for (int i = 0; i < k; i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

#define puthex(var) _puthex(#var, var)
#define puthex_n(var, n) _puthex_n(#var, var, n)

TEST_F(PsaKDFunction, aes_hkdf )
{
    psa_status_t status;
    size_t olen;

    /* old key */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attr, 256);

    psa_key_handle_t key;
    status = psa_generate_key(&attr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> old_key(32);
    status = psa_export_key(key, old_key.data(), old_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    old_key.resize(olen);
    puthex(old_key);

    /* new key */
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> salt(16);
    status = psa_generate_random(salt.data(), salt.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op,
        PSA_KEY_DERIVATION_INPUT_SALT,
        salt.data(),
        salt.size()
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_key(
        &op,
        PSA_KEY_DERIVATION_INPUT_SECRET,
        key
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> info(16);
    std::iota(info.begin(), info.end(), 0);
    status = psa_key_derivation_input_bytes(
        &op,
        PSA_KEY_DERIVATION_INPUT_INFO,
        info.data(),
        info.size()
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_key_attributes_t nkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&nkattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&nkattr, PSA_ALG_GCM);
    psa_set_key_type(&nkattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&nkattr, 256);

    psa_key_handle_t nkey;
    status = psa_key_derivation_output_key(&nkattr, &op, &nkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> raw_key(32);
    status = psa_export_key(nkey, raw_key.data(), raw_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    raw_key.resize(olen);
    puthex(raw_key);
}

TEST_F(PsaKDFunction, aes_hkdf_extract )
{
    psa_status_t status;
    size_t olen;

    /* old key */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attr, 256);

    psa_key_handle_t key;
    status = psa_generate_key(&attr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> old_key(32);
    status = psa_export_key(key, old_key.data(), old_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    old_key.resize(olen);
    puthex(old_key);

    /* new key */
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> salt(16);
    status = psa_generate_random(salt.data(), salt.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op,
        PSA_KEY_DERIVATION_INPUT_SALT,
        salt.data(),
        salt.size()
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_key(
        &op,
        PSA_KEY_DERIVATION_INPUT_SECRET,
        key
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_key_attributes_t nkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&nkattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&nkattr, PSA_ALG_GCM);
    psa_set_key_type(&nkattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&nkattr, 256);

    psa_key_handle_t nkey;
    status = psa_key_derivation_output_key(&nkattr, &op, &nkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> raw_key(32);
    status = psa_export_key(nkey, raw_key.data(), raw_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    raw_key.resize(olen);
    puthex(raw_key);
}

TEST_F(PsaKDFunction, aes_hkdf_expand )
{
    psa_status_t status;
    size_t olen;

    /* old key */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attr, 256);

    psa_key_handle_t key;
    status = psa_generate_key(&attr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> old_key(32);
    status = psa_export_key(key, old_key.data(), old_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    old_key.resize(olen);
    puthex(old_key);

    /* new key */
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_key(
        &op,
        PSA_KEY_DERIVATION_INPUT_SECRET,
        key
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> info(16);
    std::iota(info.begin(), info.end(), 0);

    status = psa_key_derivation_input_bytes(
        &op,
        PSA_KEY_DERIVATION_INPUT_INFO,
        info.data(),
        info.size()
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_key_attributes_t nkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&nkattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&nkattr, PSA_ALG_GCM);
    psa_set_key_type(&nkattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&nkattr, 256);

    psa_key_handle_t nkey;
    status = psa_key_derivation_output_key(&nkattr, &op, &nkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> raw_key(32);
    status = psa_export_key(nkey, raw_key.data(), raw_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    raw_key.resize(olen);
    puthex(raw_key);
}

TEST_F(PsaKDFunction, chachapoly_hkdf_expand )
{
    psa_status_t status;
    size_t olen;

    /* old key */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attr, 256);

    psa_key_handle_t key;
    status = psa_generate_key(&attr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> old_key(32);
    status = psa_export_key(key, old_key.data(), old_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    old_key.resize(olen);
    puthex(old_key);

    /* new key */
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_key(
        &op,
        PSA_KEY_DERIVATION_INPUT_SECRET,
        key
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> info(16);
    std::iota(info.begin(), info.end(), 0);

    status = psa_key_derivation_input_bytes(
        &op,
        PSA_KEY_DERIVATION_INPUT_INFO,
        info.data(),
        info.size()
        );
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_key_attributes_t nkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&nkattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&nkattr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305));
    psa_set_key_type(&nkattr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&nkattr, 256);

    psa_key_handle_t nkey;
    status = psa_key_derivation_output_key(&nkattr, &op, &nkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> raw_key(32);
    status = psa_export_key(nkey, raw_key.data(), raw_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    raw_key.resize(olen);
    puthex(raw_key);
}
