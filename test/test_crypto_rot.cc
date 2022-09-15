#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <enclave.h>
#include <vector>
using namespace std;

class CryptoRot_Test : public ::testing::Test {
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

TEST_F(CryptoRot_Test, importRot)
{
    struct enclave_key_store_t key;
    EXPECT_EQ(enclave_key_native(&key), ERR_OK);
}

TEST_F(CryptoRot_Test, exportRotPubkey)
{
    struct enclave_key_store_t key;
    EXPECT_EQ(enclave_key_native(&key), ERR_OK);
    struct crypto_ds_public_key_t device_identity;
    EXPECT_EQ(crypto_ds_export_public_key(&key.device_key, &device_identity), ERR_OK);
    key_print("device_identity", &device_identity, sizeof(device_identity));
}

TEST_F(CryptoRot_Test, signSession)
{
    struct enclave_key_store_t key;
    EXPECT_EQ(enclave_key_native(&key), ERR_OK);
    struct crypto_ds_public_key_t device_identity;
    EXPECT_EQ(crypto_ds_export_public_key(&key.device_key, &device_identity), ERR_OK);
    uint8_t sha[32];
    uint8_t binary[64] = {"my code and data ..."};
    crypto_hash_context_t hash;
    crypto_hash_init(&hash);
    crypto_hash_append(&hash, binary, 64);
    crypto_hash_report(&hash, sha);
    key_print("sha256<binary>", sha, sizeof(sha));
    crypto_ds_signature_t signature;
    EXPECT_EQ(crypto_sign_hashed(&key.session.client, sha, &signature), ERR_OK);
    key_print("signature", &signature, sizeof(signature));
}

TEST_F(CryptoRot_Test, verifySession)
{
    struct enclave_key_store_t key;
    EXPECT_EQ(enclave_key_native(&key), ERR_OK);
    struct crypto_ds_public_key_t device_identity;
    EXPECT_EQ(crypto_ds_export_public_key(&key.device_key, &device_identity), ERR_OK);
    uint8_t sha[32];
    uint8_t binary[64] = {"my code and data ..."};
    crypto_hash_context_t hash;
    crypto_hash_init(&hash);
    crypto_hash_append(&hash, binary, 64);
    crypto_hash_report(&hash, sha);
    key_print("sha256<binary>", sha, sizeof(sha));
    crypto_ds_signature_t signature;
    EXPECT_EQ(crypto_sign_hashed(&key.session.client, sha, &signature), ERR_OK);
    key_print("signature", signature.signature, signature.len);

    struct crypto_ds_context_t clt;
    crypto_ds_init(&clt);
    // verify session key
    EXPECT_EQ(crypto_ds_import_public_key(&clt, &device_identity), ERR_OK);
    int match;
    EXPECT_EQ(crypto_verify(&clt, key.session.cert.pk.key,
        key.session.cert.pk.len, &key.session.cert.sig, &match), ERR_OK);
    EXPECT_EQ(match, 1);
    key_print("session pubkey", key.session.cert.pk.key, key.session.cert.pk.len);
    key_print("session signature", key.session.cert.sig.signature, key.session.cert.sig.len);

    // verify signature
    crypto_ds_init(&clt);
    crypto_ds_import_public_key(&clt, &key.session.cert.pk);
    EXPECT_EQ(crypto_verify_hashed(&clt, sha, &signature, &match), ERR_OK);
    EXPECT_EQ(match, 1);
}


