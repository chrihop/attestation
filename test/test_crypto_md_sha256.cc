#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <enclave.h>
#include <vector>
using namespace std;

class CryptoSha256_Test : public ::testing::Test {
protected:

    crypto_hash_context_t ctx;

    void SetUp() override
    {
        crypto_init();
    }

    void TearDown() override
    {
    }
};

static void key_print(const char * name, void * key, size_t len)
{
    printf("%s (size %zu): ", name, len);
    auto * p = (uint8_t *) key;
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}

TEST_F(CryptoSha256_Test, sha256Empty)
{
    crypto_hash_init(&ctx);
    crypto_hash_append(&ctx, (message_t) "", 0);
    unsigned char digest[CRYPTO_HASH_SIZE];
    crypto_hash_report(&ctx, digest);
    key_print("sha256Empty", digest, CRYPTO_HASH_SIZE);
    string hex;
    for_each(digest, digest + CRYPTO_HASH_SIZE, [&hex](unsigned char c) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    });
    EXPECT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(CryptoSha256_Test, sha256Str)
{
    crypto_hash_init(&ctx);
    string msg = "plain text to hash.";
    crypto_hash_append(&ctx, (message_t) msg.c_str(), msg.size());
    unsigned char digest[CRYPTO_HASH_SIZE];
    crypto_hash_report(&ctx, digest);
    key_print("sha256Str", digest, CRYPTO_HASH_SIZE);
    string hex;
    for_each(digest, digest + CRYPTO_HASH_SIZE, [&hex](unsigned char c) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    });
    EXPECT_EQ(hex, "a5ede9aedc01a2386dd410cf26ccc28f2db98d87b29471479ef4841c9821583c");
}

