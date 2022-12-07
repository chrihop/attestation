#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <numeric>
#include <vector>
using namespace std;

#include <enclave.h>

struct openbox_t
{
    uint8_t data[8192 + 16];
    size_t  len;
};

class ChachaPoly : public ::testing::Test
{
protected:
    crypto_rac_context_t                writer, reader;
    uint8_t                             key[32];
    uint8_t                             msg[8192];
    vector<openbox_t>                   channel;
    uint8_t                             output[8192];
    unordered_map<int, vector<uint8_t>> ts;

    void                                SetUp() override
    {
        crypto_init();
        std::iota(key, key + 32, 0);
    }

    void TearDown() override { }
};

static void
key_print(const char* name, void* key, size_t len)
{
    printf("%s (size %zu): ", name, len);
    uint8_t* p = (uint8_t*)key;
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}

static openbox_t cur;

TEST_F(ChachaPoly, encDec)
{
    crypto_rac_init(&writer, key, 32);
    crypto_rac_init(&reader, key, 32);

    for (int i = 0; i < 10; i++)
    {
        std::iota(msg, msg + 8192, i);
        size_t  nonce_len;
        uint8_t nonce[12];
        crypto_rac_encrypt(
            &writer, msg, 8192, cur.data, &cur.len, nonce, &nonce_len);
        EXPECT_EQ(cur.len, 8192 + 16);
        vector<uint8_t> _nonce(nonce, nonce + nonce_len);
        ts[i] = _nonce;
        EXPECT_NE(ts[i], vector<uint8_t>(12, 0));
        channel.emplace_back(cur);
    }

    int k = 100;
    while (k -- > 0)
    {
        int i = rand() % 10;
        int succ = crypto_rac_decrypt(&reader, ts[i].data(), ts[i].size(),
            channel[i].data, channel[i].len, output, &cur.len);
        EXPECT_EQ(succ, 1);
        std::iota(msg, msg + 8192, i);
        EXPECT_EQ(vector<uint8_t>(output, output + 8192),
            vector<uint8_t>(msg, msg + 8192));
    }
}
