#include <gtest/gtest.h>
#include <psa/crypto.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <abstraction.h>
#include <vector>
#include <numeric>
using namespace std;

class PsaSymmetricCipher : public ::testing::Test {
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

TEST_F(PsaSymmetricCipher, aes128_keygen)
{
    psa_status_t status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CTR));

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, 128);

    psa_key_handle_t key_handle;
    status = psa_generate_key(&key_attr, &key_handle);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> key(16);
    size_t len;
    status = psa_export_key(key_handle, key.data(), key.size(), &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, 16);
    vector<unsigned char> zeros(16, 0);
    EXPECT_NE(key, zeros);
    puthex(key);
}

TEST_F(PsaSymmetricCipher, aes128_keygen_memory_leak)
{
    psa_status_t status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CTR));

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, 128);

#if defined(MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
    psa_key_handle_t key_handle;
    status = psa_generate_key(&key_attr, &key_handle);
    ASSERT_EQ(status, PSA_SUCCESS);
    status = psa_destroy_key(key_handle);
    ASSERT_EQ(status, PSA_SUCCESS);
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    EXPECT_EQ(used_before, used_after);
    EXPECT_EQ(blocks_before, blocks_after);

    int k = 10;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
    while (k-- > 0)
    {
        psa_key_handle_t key_handle;
        status = psa_generate_key(&key_attr, &key_handle);
        ASSERT_EQ(status, PSA_SUCCESS);
        status = psa_destroy_key(key_handle);
        ASSERT_EQ(status, PSA_SUCCESS);
    }
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    EXPECT_EQ(used_before, used_after);
    EXPECT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(PsaSymmetricCipher, aes128_ctr)
{
    psa_status_t status;
    psa_key_attributes_t sender_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&sender_key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&sender_key_attr, PSA_ALG_CTR);

    psa_set_key_type(&sender_key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sender_key_attr, 128);

    psa_key_handle_t sender_key, receiver_key;
    status = psa_generate_key(&sender_key_attr, &sender_key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> key(16);
    size_t len;
    status = psa_export_key(sender_key, key.data(), key.size(), &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, 16);

    psa_key_attributes_t receiver_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&receiver_key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&receiver_key_attr, PSA_ALG_CTR);
    psa_set_key_type(&receiver_key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&receiver_key_attr, 128);

    status = psa_import_key(&receiver_key_attr, key.data(), key.size(), &receiver_key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> data(1024);
    iota(data.begin(), data.end(), 0);

    vector<unsigned char> ciphertext(1024 + 16);

    status = psa_cipher_encrypt(
        sender_key,
        PSA_ALG_CTR,
        data.data(),
        data.size(),
        ciphertext.data(),
        ciphertext.size(),
        &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, 1024 + 16);
    _puthex_n("iv", ciphertext, 12);

    vector<unsigned char> plaintext(1024);
    status = psa_cipher_decrypt(
        receiver_key,
        PSA_ALG_CTR,
        ciphertext.data(),
        ciphertext.size(),
        plaintext.data(),
        plaintext.size(),
        &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, 1024);
}

TEST_F(PsaSymmetricCipher, aes_gcm_aead)
{
    psa_status_t status;
    psa_key_attributes_t sender_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&sender_key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&sender_key_attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM));
    psa_set_key_type(&sender_key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sender_key_attr, 128);

    psa_key_handle_t sender_key;
    status = psa_generate_key(&sender_key_attr, &sender_key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> key(16);
    size_t len;
    status = psa_export_key(sender_key, key.data(), key.size(), &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, 16);

    psa_key_attributes_t receiver_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&receiver_key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&receiver_key_attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM));
    psa_set_key_type(&receiver_key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&receiver_key_attr, 128);

    psa_key_handle_t receiver_key;
    psa_import_key(&receiver_key_attr, key.data(), key.size(), &receiver_key);

    vector<unsigned char> data(1024);
    iota(data.begin(), data.end(), 0);

    vector<unsigned char> iv(PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_GCM));
    psa_generate_random(iv.data(), iv.size());
    puthex(iv);
    ASSERT_GT(iv.size(), 0);

    vector<unsigned char> ad(8);
    iota(ad.begin(), ad.end(), 0);
    puthex(ad);
    ASSERT_GT(ad.size(), 0);

    vector<unsigned char> ciphertext(
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_AES,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
            data.size())
        );
    ASSERT_GE(ciphertext.size(), data.size());
    std::printf("ciphertext.size() = %zu\n", ciphertext.size());

    status = psa_aead_encrypt(
        sender_key,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
        iv.data(),
        iv.size(),
        ad.data(),
        ad.size(),
        data.data(),
        data.size(),
        ciphertext.data(),
        ciphertext.size(),
        &len);

    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_AES,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
            data.size()));

    vector<unsigned char> tag(PSA_AEAD_TAG_LENGTH(
        PSA_KEY_TYPE_AES,
        128,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM)));
    ASSERT_GT(tag.size(), 0);
    copy(ciphertext.end() - tag.size(), ciphertext.end(), tag.begin());
    puthex(tag);

    vector<unsigned char> plaintext(
        PSA_AEAD_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_AES,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
            ciphertext.size())
        );
    ASSERT_GE(plaintext.size(), data.size());
    std::printf("plaintext.size() = %zu\n", plaintext.size());

    status = psa_aead_decrypt(
        receiver_key,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
        iv.data(),
        iv.size(),
        ad.data(),
        ad.size(),
        ciphertext.data(),
        ciphertext.size(),
        plaintext.data(),
        plaintext.size(),
        &len);

    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, PSA_AEAD_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_AES,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
            ciphertext.size()));
    EXPECT_EQ(plaintext, data);
}

TEST_F(PsaSymmetricCipher, aes_chachapoly_aead)
{
    psa_status_t status;
    psa_key_attributes_t sender_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&sender_key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&sender_key_attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305));
    psa_set_key_type(&sender_key_attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&sender_key_attr, 256);

    psa_key_handle_t sender_key;
    status = psa_generate_key(&sender_key_attr, &sender_key);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<unsigned char> key(32);
    size_t len;
    status = psa_export_key(sender_key, key.data(), key.size(), &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, 32);

    psa_key_attributes_t receiver_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&receiver_key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&receiver_key_attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305));
    psa_set_key_type(&receiver_key_attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&receiver_key_attr, 256);

    psa_key_handle_t receiver_key;
    psa_import_key(&receiver_key_attr, key.data(), key.size(), &receiver_key);

    vector<unsigned char> data(1024);
    iota(data.begin(), data.end(), 0);

    vector<unsigned char> iv(PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_CHACHA20,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305)));
    psa_generate_random(iv.data(), iv.size());
    puthex(iv);
    ASSERT_GT(iv.size(), 0);

    vector<unsigned char> ad(8);
    iota(ad.begin(), ad.end(), 0);
    puthex(ad);
    ASSERT_GT(ad.size(), 0);

    vector<unsigned char> ciphertext(
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            data.size())
        );
    ASSERT_GE(ciphertext.size(), data.size());

    status = psa_aead_encrypt(
        sender_key,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
        iv.data(),
        iv.size(),
        ad.data(),
        ad.size(),
        data.data(),
        data.size(),
        ciphertext.data(),
        ciphertext.size(),
        &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            data.size()));

    vector<unsigned char> tag(PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_CHACHA20, 128, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305)));
    ASSERT_GT(tag.size(), 0);
    copy(ciphertext.end() - tag.size(), ciphertext.end(), tag.begin());
    puthex(tag);

    vector<unsigned char> plaintext(
        PSA_AEAD_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            ciphertext.size())
        );
    ASSERT_GE(plaintext.size(), data.size());

    status = psa_aead_decrypt(
        receiver_key,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
        iv.data(),
        iv.size(),
        ad.data(),
        ad.size(),
        ciphertext.data(),
        ciphertext.size(),
        plaintext.data(),
        plaintext.size(),
        &len);
    ASSERT_EQ(status, PSA_SUCCESS);
    EXPECT_EQ(len, PSA_AEAD_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            ciphertext.size()));
    EXPECT_EQ(plaintext, data);
}
