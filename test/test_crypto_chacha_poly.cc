#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <numeric>
#include <vector>
using namespace std;

#include <enclave.h>

class ChachaPoly : public ::testing::Test {
protected:
    crypto_sc_mac_context_t peer1, peer2;
    uint8_t                 key[32];
    uint8_t                 msg[8192];
    uint8_t                 channel[8192 + 16];
    uint8_t                 output[8192];
    uint8_t                 empty_block[8192 + 16];

    void SetUp() override
    {
        crypto_init();
        std::iota(key, key+32, 0);
    }

    void TearDown() override
    {
    }
};

static void key_print(const char * name, void * key, size_t len)
{
    printf("%s (size %zu): ", name, len);
    uint8_t * p = (uint8_t *) key;
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}

TEST_F(ChachaPoly, encDec)
{
    crypto_sc_mac_init(&peer1, key, 32, 1);
    crypto_sc_mac_init(&peer2, key, 32, 0);

    for (int i = 0; i < 10; i++)
    {
        std::iota(msg, msg+8192, i);
        size_t len, olen;
        crypto_sc_mac_encrypt(&peer1, msg, 8192, channel, &len);
        EXPECT_EQ(len, 8192 + 16);
        int succ = crypto_sc_mac_decrypt(&peer2, channel, len, output, &olen);
        EXPECT_EQ(succ, 1);
        EXPECT_EQ(vector<uint8_t>(output, output+8192), vector<uint8_t>(msg, msg+8192));
    }
}

TEST_F(ChachaPoly, messageDrop)
{
    crypto_sc_mac_init(&peer1, key, 32, 1);
    crypto_sc_mac_init(&peer2, key, 32, 0);

    size_t dropped_bytes = 0;
    size_t len;
    size_t olen;
    for (int i = 0; i < 9; i++)
    {
        std::iota(msg, msg+8192, i);
        crypto_sc_mac_encrypt(&peer1, msg, 8192, channel, &len);
        dropped_bytes += len;
        EXPECT_EQ(len, 8192 + 16);
    }

    std::iota(msg, msg+8192, 10);
    crypto_sc_mac_encrypt(&peer1, msg, 8192, channel, &len);
    EXPECT_EQ(len, 8192 + 16);

    for (int i = 0; i < 9; i++)
    {
        int succ = crypto_sc_mac_decrypt(&peer2, empty_block, 8192 + 16, output, &olen);
        EXPECT_EQ(succ, 0);
        EXPECT_EQ(olen, 8192);
        dropped_bytes -= 8192 + 16;
    }
    EXPECT_EQ(dropped_bytes, 0);

    int succ = crypto_sc_mac_decrypt(&peer2, channel, 8192 + 16, output, &olen);
    EXPECT_EQ(succ, 1);
    EXPECT_EQ(olen, 8192);
    EXPECT_EQ(vector<uint8_t>(output, output+8192), vector<uint8_t>(msg, msg+8192));
}
