#include <gtest/gtest.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <numeric>
#include <psa/crypto.h>
#include <vector>
using namespace std;

#include <abstraction.h>


class PsaAsymmetricCipher : public ::testing::Test
{
public:
    void SetUp() override { crypto_init(); }

    void TearDown() override { mbedtls_psa_crypto_free(); }
};

void
_puthex(const char* name, const vector<unsigned char>& data)
{
    std::printf("%s (size %zu): ", name, data.size());
    for (int i = 0; i < data.size(); i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

void
_puthex_n(const char* name, const vector<unsigned char>& data, size_t n)
{
    size_t k = std::min(n, data.size());
    std::printf("%s (size %zu): ", name, k);
    for (int i = 0; i < k; i++)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

#define puthex(var)      _puthex(#var, var)
#define puthex_n(var, n) _puthex_n(#var, var, n)

TEST_F(PsaAsymmetricCipher, rsa_keygen)
{
    psa_status_t         status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(
        &key_attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, 2048);

    psa_key_handle_t key_pair;
    status = psa_generate_key(&key_attr, &key_pair);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> pubkey(
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, 2048));
    size_t olen;
    status
        = psa_export_public_key(key_pair, pubkey.data(), pubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_LE(olen, pubkey.size());
    puthex_n(pubkey, olen);
    psa_destroy_key(key_pair);
}

TEST_F(PsaAsymmetricCipher, ecc_pubkey)
{
    psa_status_t         status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(
        &key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, 256);

    psa_key_handle_t key_pair;
    status = psa_generate_key(&key_attr, &key_pair);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> pubkey(PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256));
    size_t          olen;
    status
        = psa_export_public_key(key_pair, pubkey.data(), pubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_LE(olen, pubkey.size());
    puthex_n(pubkey, olen);
    psa_destroy_key(key_pair);
}

TEST_F(PsaAsymmetricCipher, rsa_keygen_memory_leak)
{
    psa_status_t         status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(
        &key_attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, 2048);

#ifdef MBEDTLS_MEMORY_DEBUG
    size_t used_before, block_before, used_after, block_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &block_before);
    psa_key_handle_t key_pair;
    status = psa_generate_key(&key_attr, &key_pair);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> pubkey(
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, 2048));
    size_t olen;
    status
        = psa_export_public_key(key_pair, pubkey.data(), pubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_LE(olen, pubkey.size());
    puthex_n(pubkey, olen);
    psa_destroy_key(key_pair);
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &block_after);
    ASSERT_EQ(used_before, used_after);
#endif
}

/**
 * ssh -t rsa -b 2048 -f rsa-text.txt -m pem
 */
static const char rsa_key[]
    = "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIIEpQIBAAKCAQEAyYmJzAUYLcmXVlQViDjJBTJ/TQbr2Ot5yP9aZPlVG9ANYt+K\n"
      "eO2h5yLd1u2SXaeTRal13yEr/Z0x7Dw5lQ+yoMTpA2wyAJhnwCtRZR1IZKZXEVmJ\n"
      "rbVAjOVP/59DPM7sDNBHjG9/oAKrOttPwSnPKG0UDv9PByrpXWhRqsEfC5Oq8Od8\n"
      "rFdRWxsVqiGehv/KCCgtshhl3pBtMmpk06Cg+dp5DQR+FpnFPq0b3r/tj53P5Xbd\n"
      "UnIHlun/a4+34DoGl4xeVygxPvSKQGON5lcH3ilmeKFBrGbKOHl2jE4jMnwc0wzl\n"
      "1VpjrTEOrVIIydXTMzZC4YplOWsis4nCp7HQkQIDAQABAoIBAQCYc5EoIsZqhG8V\n"
      "X5+2HvZ5FvzTIKQxv9atI/SWI0GtO1GU9HJEDcYGGQrktWudqtCtxoWilu429702\n"
      "7UvFpU1DbhCxhRvB9YeuB1aX/XGwqV99gVSzcUN2EVTVkf0Dt6c5/ifRZNqPCNXM\n"
      "PO/0t5K8Ct88hQab7mr/PJVibJn2X5JKZBs2cVKSRpQHP+e3D4RNYiKLvoywIxEr\n"
      "rR/nvJ4azB792NddsUXGi6nF0mSQl5Ej1kNoEmGBDOopmK0tqZyisbzy/iFcX+B7\n"
      "xPrVEbd3urnnPSqd4NSQ6LQDH/noFQrlm4lnVh62qNdTACRDayW+guzho4jaCFOY\n"
      "FMtG+ofBAoGBAPQhvV+7zb4gKTxnk7zPcNfdISe3Ld1faq5bA38Jbg7grFK64sLR\n"
      "JVTe9eogLt1Nxrz/DTcqnTRjC7J5EWaPkjRlUcqSxdoEDBg/0X7poEb6nqwBZqQi\n"
      "mw4aMY0YOCJ1ZGns4tUz86AdasPr05dbGYRVcs0pQiIosL/9/VOrwAcJAoGBANNV\n"
      "s9iw1TXpE1m2c/bdBBziYns/Y41M+0KylPTf0Ol20OQQJf2amqjgzjVIyahkBkCm\n"
      "aht84w3A9uPSvyQiaKeg74L0cwIJ7AzqakCMyfCR5lZ2Q1E53JPA4/hosxqVaIeD\n"
      "jBX/FQJHOrZKIMy43cZAh6OnqafXSLRT2yUYXhdJAoGAMuZV9X/ShbFu54kw5Ezb\n"
      "2iXgo8ctaNpcA742HGZ6698sDpOoc7XncqqJ2yaansl4hi8nMjlQTXvZFHzpg9ir\n"
      "QwFc7D9twObXHrcvlqZfJG1cZ8BjBhWw/l+3tRM3oPeY1/zrzkfmo5t+hxrEIup7\n"
      "h3vJU70mbLjPIThzeN52SwECgYEAtbxPipqW32Nt1opGMxZhQQ2VLvOWAp8eu36j\n"
      "Bemq1/nrLRSN9waK1YttCPltITfTAKmbOcQt5Vf5eHV1FffZE74b+fuJI0mxCnJT\n"
      "qOrphc2RzOyqeyFNBGquIKK40rWFTHPdddUEFg929+fLSQH5BVHc0umNxd4mkZxD\n"
      "KiVIVLECgYEArzAZSlAoTcEa8w/P+kfzrXWJ9DTznRmys7pb4itR58uXhuwkbEvr\n"
      "LwcfW1hmdudxZ+FiZZKiD00bzhbKCsu2/VSMkMLVil+jeOVhfEDyLBe61Rmi6E9d\n"
      "BA07xTS/taKUHaEtzTaiIqLwkUDF/ehIbF5YBdMUUUcOCk0R9B/4L3s=\n"
      "-----END RSA PRIVATE KEY-----\0";

/**
 * ssh -f rsa-text.txt -e -m pem > rsa-pubkey.txt
 */
static const char rsa_pubkey[]
    = "-----BEGIN RSA PUBLIC KEY-----\n"
      "MIIBCgKCAQEAyYmJzAUYLcmXVlQViDjJBTJ/TQbr2Ot5yP9aZPlVG9ANYt+KeO2h\n"
      "5yLd1u2SXaeTRal13yEr/Z0x7Dw5lQ+yoMTpA2wyAJhnwCtRZR1IZKZXEVmJrbVA\n"
      "jOVP/59DPM7sDNBHjG9/oAKrOttPwSnPKG0UDv9PByrpXWhRqsEfC5Oq8Od8rFdR\n"
      "WxsVqiGehv/KCCgtshhl3pBtMmpk06Cg+dp5DQR+FpnFPq0b3r/tj53P5XbdUnIH\n"
      "lun/a4+34DoGl4xeVygxPvSKQGON5lcH3ilmeKFBrGbKOHl2jE4jMnwc0wzl1Vpj\n"
      "rTEOrVIIydXTMzZC4YplOWsis4nCp7HQkQIDAQAB\n"
      "-----END RSA PUBLIC KEY-----\0";

TEST_F(PsaAsymmetricCipher, import_key)
{
    psa_status_t         status;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);

    psa_key_handle_t key;
    status
        = psa_import_key(&attr, (const uint8_t*)rsa_key, sizeof(rsa_key), &key);
    ASSERT_EQ(status, PSA_SUCCESS);
    psa_destroy_key(key);
}

TEST_F(PsaAsymmetricCipher, rsa_import_pubkey)
{
    psa_key_attributes_t vkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&vkattr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&vkattr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&vkattr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&vkattr, 2048);

    psa_status_t     status;
    psa_key_handle_t vkey;
    status = psa_import_key(
        &vkattr, (const uint8_t*)rsa_pubkey, sizeof(rsa_pubkey), &vkey);
    ASSERT_EQ(status, PSA_SUCCESS);
    psa_destroy_key(vkey);
}

TEST_F(PsaAsymmetricCipher, rsa_import_key_sign_verify)
{
    psa_key_attributes_t skattr = PSA_KEY_ATTRIBUTES_INIT,
                         vkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&skattr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_usage_flags(&vkattr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&skattr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_algorithm(&vkattr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&skattr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_type(&vkattr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&skattr, 2048);
    psa_set_key_bits(&vkattr, 2048);

    psa_status_t     status;
    psa_key_handle_t skey, vkey;
    status = psa_import_key(
        &skattr, (const uint8_t*)rsa_key, sizeof(rsa_key), &skey);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_import_key(
        &vkattr, (const uint8_t*)rsa_pubkey, sizeof(rsa_pubkey), &vkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> message(1024);
    std::iota(message.begin(), message.end(), 0);

    vector<uint8_t> signature(1024);
    size_t          olen = 0;
    status = psa_sign_message(skey, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        message.data(), message.size(), signature.data(), signature.size(),
        &olen);
    signature.resize(olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    puthex(signature);

    status
        = psa_verify_message(vkey, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
            message.data(), message.size(), signature.data(), signature.size());
    ASSERT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaAsymmetricCipher, ecdsa256_keygen)
{
    psa_status_t         status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, 2048);

    psa_key_handle_t key_pair;
    status = psa_generate_key(&key_attr, &key_pair);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> pubkey(
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, 2048));
    size_t olen;
    status
        = psa_export_public_key(key_pair, pubkey.data(), pubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_LE(olen, pubkey.size());
    puthex_n(pubkey, olen);
    psa_destroy_key(key_pair);
}

/**
 * openssl ecparam -name secp256k1 -genkey -noout -out ./ecdsa.txt
 */
    char ecdsa_key[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIIgZK7Nmtr7Sk/x7bgKvldJwcef+p1GiWWwudWV9Es7yoAcGBSuBBAAK\n"
        "oUQDQgAEH6ZLw2s0NqHtnzP83vVdd6sInMk20M0IkZxSA91uBTwrP8FD505M/HDH\n"
        "aJ2tsxQySd+9x/4qlNQCiOpDUb3eTg==\n"
        "-----END EC PRIVATE KEY-----\0";

/**
 * openssl ec -in ./ecdsa.txt -pubout -out ./ecdsa_pub.txt
 */
    char ecdsa_pubkey[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEH6ZLw2s0NqHtnzP83vVdd6sInMk20M0I\n"
        "kZxSA91uBTwrP8FD505M/HDHaJ2tsxQySd+9x/4qlNQCiOpDUb3eTg==\n"
        "-----END PUBLIC KEY-----\0";

TEST_F(PsaAsymmetricCipher, ecdsa256_import_key_sign_verify)
{
    psa_key_attributes_t skattr = PSA_KEY_ATTRIBUTES_INIT,
                         vkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&skattr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_usage_flags(&vkattr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&skattr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_algorithm(&vkattr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(
        &skattr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    psa_set_key_type(
        &vkattr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1));

    psa_status_t       status;
    psa_key_handle_t   skey, vkey;

    size_t             olen = 0;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_call(mbedtls_pk_parse_key, &pk, (const uint8_t*)ecdsa_key,
        sizeof(ecdsa_key), NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    ASSERT_EQ(mbedtls_pk_get_type(&pk), MBEDTLS_PK_ECKEY);
    mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(pk);
    vector<uint8_t>      curve(256);
    mbedtls_call(mbedtls_ecp_write_key, ecp, curve.data(),
        PSA_BITS_TO_BYTES(ecp->private_grp.nbits));
    curve.resize(PSA_BITS_TO_BYTES(ecp->private_grp.nbits));
    puthex(curve);

    mbedtls_pk_free(&pk);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    status = psa_import_key(&skattr, curve.data(), curve.size(), &skey);
    ASSERT_EQ(status, PSA_SUCCESS);

    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_call(mbedtls_pk_parse_public_key, &pk, (const uint8_t*)ecdsa_pubkey,
        sizeof(ecdsa_pubkey));
    ASSERT_EQ(mbedtls_pk_get_type(&pk), MBEDTLS_PK_ECKEY);
    ecp                         = mbedtls_pk_ec(pk);
    size_t          pubkey_size = PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256);
    vector<uint8_t> pubkey(pubkey_size);
    mbedtls_call(mbedtls_ecp_point_write_binary, &ecp->private_grp,
        &ecp->private_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pubkey.data(),
        pubkey_size);
    pubkey.resize(olen);
    puthex(pubkey);

    mbedtls_pk_free(&pk);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    status = psa_import_key(&vkattr, pubkey.data(), pubkey.size(), &vkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> message(1024);
    std::iota(message.begin(), message.end(), 0);

    vector<uint8_t> signature(PSA_ECDSA_SIGNATURE_SIZE(256));
    status
        = psa_sign_message(skey, PSA_ALG_ECDSA(PSA_ALG_SHA_256), message.data(),
            message.size(), signature.data(), signature.size(), &olen);
    signature.resize(olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    puthex(signature);

    status = psa_verify_message(vkey, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        message.data(), message.size(), signature.data(), signature.size());
    ASSERT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaAsymmetricCipher, ecdh_raw_exchange)
{
    psa_status_t         status;

    psa_key_attributes_t akattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &akattr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&akattr, PSA_ALG_ECDH);
    psa_set_key_type(
        &akattr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&akattr, 255);

    psa_key_handle_t akey;
    status = psa_generate_key(&akattr, &akey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> apubkey(PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(255));
    size_t          olen = 0;
    status = psa_export_public_key(akey, apubkey.data(), apubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    apubkey.resize(olen);
    puthex(apubkey);

    psa_key_attributes_t bkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &bkattr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&bkattr, PSA_ALG_ECDH);
    psa_set_key_type(
        &bkattr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&bkattr, 255);

    psa_key_handle_t bkey;
    status = psa_generate_key(&bkattr, &bkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> a_secrete(256);

    status = psa_raw_key_agreement(PSA_ALG_ECDH, bkey, apubkey.data(),
        apubkey.size(), a_secrete.data(), a_secrete.size(), &olen);
    a_secrete.resize(olen);
    puthex(a_secrete);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> bpubkey(PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(255));
    status = psa_export_public_key(bkey, bpubkey.data(), bpubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    bpubkey.resize(olen);
    puthex(bpubkey);

    vector<uint8_t> b_secrete(256);
    status = psa_raw_key_agreement(PSA_ALG_ECDH, akey, bpubkey.data(),
        bpubkey.size(), b_secrete.data(), b_secrete.size(), &olen);
    b_secrete.resize(olen);
    puthex(b_secrete);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_EQ(a_secrete, b_secrete);
}

TEST_F(PsaAsymmetricCipher, ecdh_key_exchange)
{
    psa_status_t         status;
    size_t               olen;

    psa_key_attributes_t akattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &akattr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&akattr, PSA_ALG_ECDH);
    psa_set_key_type(
        &akattr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&akattr, 255);

    psa_key_handle_t akey;
    status = psa_generate_key(&akattr, &akey);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> apubkey(PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(255));
    status = psa_export_public_key(akey, apubkey.data(), apubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    apubkey.resize(olen);
    puthex(apubkey);

    psa_key_attributes_t bkattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &bkattr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&bkattr, PSA_ALG_ECDH);
    psa_set_key_type(
        &bkattr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&bkattr, 255);

    psa_key_handle_t bkey;
    status = psa_generate_key(&bkattr, &bkey);
    ASSERT_EQ(status, PSA_SUCCESS);

    std::printf("size of psa_key_derivation_operation_t: %zu\n",
        sizeof(psa_key_derivation_operation_t));
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status                            = psa_key_derivation_setup(&op,
                                   PSA_ALG_KEY_AGREEMENT(
            PSA_ALG_ECDH, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)));
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_key_agreement(&op,
        PSA_KEY_DERIVATION_INPUT_SECRET, bkey, apubkey.data(), apubkey.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> info(16);
    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_INFO, info.data(), info.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_key_attributes_t skb_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &skb_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&skb_attr, PSA_ALG_CCM);
    psa_set_key_type(&skb_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&skb_attr, 256);

    psa_key_handle_t skb;
    status = psa_key_derivation_output_key(&skb_attr, &op, &skb);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> b_aes_key(32);
    status = psa_export_key(skb, b_aes_key.data(), b_aes_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    b_aes_key.resize(olen);
    puthex(b_aes_key);

    /* -> a */
    vector<uint8_t> bpubkey(PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(255));
    status = psa_export_public_key(bkey, bpubkey.data(), bpubkey.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    bpubkey.resize(olen);
    puthex(bpubkey);

    psa_key_derivation_operation_t op_a = PSA_KEY_DERIVATION_OPERATION_INIT;
    status                              = psa_key_derivation_setup(&op_a,
                                     PSA_ALG_KEY_AGREEMENT(
            PSA_ALG_ECDH, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)));
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_key_agreement(&op_a,
        PSA_KEY_DERIVATION_INPUT_SECRET, akey, bpubkey.data(), bpubkey.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op_a, PSA_KEY_DERIVATION_INPUT_INFO, info.data(), info.size());
    ASSERT_EQ(status, PSA_SUCCESS);

    psa_key_attributes_t ska_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &ska_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&ska_attr, PSA_ALG_CCM);
    psa_set_key_type(&ska_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&ska_attr, 256);

    psa_key_handle_t ska;
    status = psa_key_derivation_output_key(&ska_attr, &op_a, &ska);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> a_aes_key(32);
    status = psa_export_key(ska, a_aes_key.data(), a_aes_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    a_aes_key.resize(olen);
    puthex(a_aes_key);

    ASSERT_EQ(a_aes_key, b_aes_key);
}
