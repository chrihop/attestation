#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <enclave.h>
#include <vector>
using namespace std;

class CryptoECDSA_Test : public ::testing::Test {
protected:
    crypto_ds_context_t ctx;
    crypto_ds_context_t srv, clt;

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

TEST_F(CryptoECDSA_Test, digitalSign)
{
    EXPECT_EQ(crypto_ds_init(&ctx), ERR_OK);
    EXPECT_EQ(crypto_ds_gen_keypair(&ctx), ERR_OK);
    key_print("key-pair [grp]", &ctx.ecdsa_ctx.private_grp, sizeof(mbedtls_ecp_group));
    key_print("key-pair [  d]", &ctx.ecdsa_ctx.private_d, sizeof(mbedtls_mpi));
    key_print("key-pair [  Q]", &ctx.ecdsa_ctx.private_Q, sizeof(mbedtls_ecp_point));
    const char * msg = "plain text to sign.";
    crypto_ds_signature_t sig;
    EXPECT_EQ(crypto_sign(&ctx, (message_t) msg, strlen(msg), &sig), ERR_OK);
    key_print("signature", sig.signature, sig.len);
    int match;
    EXPECT_EQ(crypto_verify(&ctx, (message_t) msg, strlen(msg), &sig, &match), ERR_OK);
    EXPECT_EQ(match, true);
}

TEST_F(CryptoECDSA_Test, digitalSignPubkey)
{
    EXPECT_EQ(crypto_ds_init(&srv), ERR_OK);
    EXPECT_EQ(crypto_ds_gen_keypair(&srv), ERR_OK);
    const char * msg = "plain text to sign.";
    crypto_ds_signature_t sig;
    EXPECT_EQ(crypto_sign(&srv, (message_t) msg, strlen(msg), &sig), ERR_OK);
    key_print("signature", sig.signature, sig.len);

    crypto_ds_public_key_t pubkey;
    EXPECT_EQ(crypto_ds_export_public_key(&srv, &pubkey), ERR_OK);
    key_print("exported public key", pubkey.key, pubkey.len);

    EXPECT_EQ(crypto_ds_init(&clt), ERR_OK);
    EXPECT_EQ(crypto_ds_import_public_key(&clt, &pubkey), ERR_OK);

    int match;
    EXPECT_EQ(crypto_verify(&clt, (message_t) msg, strlen(msg), &sig, &match), ERR_OK);
    EXPECT_EQ(match, true);

    const char * msg_tampered = "plain text to xign.";
    EXPECT_EQ(crypto_verify(&clt, (message_t) msg_tampered, strlen(msg_tampered), &sig, &match), MBEDTLS_ERR_ECP_VERIFY_FAILED);
    EXPECT_EQ(match, false);
}

TEST_F(CryptoECDSA_Test, digitalSignNondeterministicSign)
{
    EXPECT_EQ(crypto_ds_init(&srv), ERR_OK);
    EXPECT_EQ(crypto_ds_gen_keypair(&srv), ERR_OK);
    const char * msg = "plain text to sign.";
    crypto_ds_signature_t sig1, sig2;
    EXPECT_EQ(crypto_sign(&srv, (message_t) msg, strlen(msg), &sig1), ERR_OK);
    key_print("signature 1", sig1.signature, sig1.len);

    EXPECT_EQ(crypto_sign(&srv, (message_t) msg, strlen(msg), &sig2), ERR_OK);
    key_print("signature 2", sig2.signature, sig2.len);

    EXPECT_NE(vector<uint8_t>(sig1.signature, sig1.signature + sig1.len), vector<uint8_t>(sig2.signature, sig2.signature + sig2.len));

    crypto_ds_public_key_t pubkey;
    EXPECT_EQ(crypto_ds_export_public_key(&srv, &pubkey), ERR_OK);
    key_print("exported public key", pubkey.key, pubkey.len);

    EXPECT_EQ(crypto_ds_init(&clt), ERR_OK);
    EXPECT_EQ(crypto_ds_import_public_key(&clt, &pubkey), ERR_OK);

    int match;
    EXPECT_EQ(crypto_verify(&clt, (message_t) msg, strlen(msg), &sig1, &match), ERR_OK);
    EXPECT_EQ(match, true);

    EXPECT_EQ(crypto_verify(&clt, (message_t) msg, strlen(msg), &sig2, &match), ERR_OK);
    EXPECT_EQ(match, true);
}
