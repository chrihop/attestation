#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <enclave.h>
#include <vector>
using namespace std;

class CryptoRng_Test : public ::testing::Test {
protected:
    uint8_t rng[32];

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

TEST_F(CryptoRng_Test, rngGen)
{
    memset(rng, 0xa0, 32);
    crypto_rng(rng, 32);
    key_print("rng", rng, 32);
    EXPECT_NE(vector<uint8_t>(rng, rng+32), vector<uint8_t>(32, 0xa0));
}


