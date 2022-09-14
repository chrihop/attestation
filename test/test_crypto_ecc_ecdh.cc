#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <enclave.h>
#include <vector>
using namespace std;

class CryptoECDH_Test : public ::testing::Test {
protected:
    crypto_dh_context_t srv, clt;
    crypto_dh_curve_t   curve;

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
    uint8_t * p = (uint8_t *) key;
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}


TEST_F(CryptoECDH_Test, keyExchange)
{
    crypto_dh_key_t shared, secrete1, secrete2;
    EXPECT_EQ(crypto_dh_genkey(&clt, &curve), ERR_OK);
    key_print("ecdh keypair: ", curve.curve, curve.len);
    EXPECT_EQ(crypto_dh_exchange_genkey(&srv, &curve, &shared, &secrete1), ERR_OK);
    key_print("ecdh shared key: ", shared.key, shared.len);
    EXPECT_EQ(crypto_dh_exchange(&clt, &shared, &secrete2), ERR_OK);
    key_print("secrete key 1: ", secrete1.key, secrete1.len);
    key_print("secrete key 2: ", secrete2.key, secrete2.len);
    EXPECT_EQ(vector<uint8_t>(secrete1.key, secrete1.key + secrete1.len),
            vector<uint8_t>(secrete2.key, secrete2.key + secrete2.len));
}
