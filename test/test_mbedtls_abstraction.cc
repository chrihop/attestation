#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <numeric>
#include <vector>
using namespace std;

#include <abstraction.h>

#define TEST_PANIC_FUNCTIONS 0

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

void _puthex_n(const char * name, const void * data, size_t n)
{
    std::printf("%s (size %zu): ", name, n);
    for (int i = 0; i < n; i++)
    {
        std::printf("%02x", ((uint8_t *)data)[i]);
    }
    std::printf("\n");
}

#define puthex(var) _puthex(#var, var)
#define puthex_n(var, n) _puthex_n(#var, var, n)

class MBedTlsAbstraction : public ::testing::Test
{
public:
    void SetUp() override { crypto_init(); }

    void TearDown() override { mbedtls_psa_crypto_free(); }
};

TEST_F(MBedTlsAbstraction, error_code)
{
#if (TEST_PANIC_FUNCTIONS)
    _mbedtls_panic(MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED, __FUNCTION__ , __FILE__, __LINE__);
    _psa_panic(PSA_ERROR_INVALID_ARGUMENT, __FUNCTION__ , __FILE__, __LINE__);
#endif
}

TEST_F(MBedTlsAbstraction, sanity)
{
#if defined(MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);

    mbedtls_calloc(1, 8);

    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before + 8, used_after);
    ASSERT_EQ(blocks_before + 1, blocks_after);
#endif
}

TEST_F(MBedTlsAbstraction, rng)
{
    vector<uint8_t> buf(32), zeros(32, 0);
    crypto_rng(buf.data(), buf.size());
    puthex(buf);
    ASSERT_NE(buf, zeros);
}

TEST_F(MBedTlsAbstraction, b64)
{
    const char * msg = "The quick brown fox jumps over the lazy dog";
    vector<uint8_t> buf(msg, msg + strlen(msg)), text(64);
    vector<uint8_t> b64(64);
    size_t olen = 0;

    crypto_b64_encode(b64.data(), b64.size(), &olen, buf.data(), buf.size());
    b64.resize(olen);
    printf("base64: %s\n", b64.data());

    crypto_b64_decode(text.data(), text.size(), &olen, b64.data(), b64.size());
    text.resize(olen);
    puthex(text);
    ASSERT_EQ(text, buf);
}

TEST_F(MBedTlsAbstraction, secure_hash)
{
    crypto_hash_context_t ctx;

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    vector<uint8_t> binary(4096 * 10);
    std::iota(binary.begin(), binary.end(), 0);

    crypto_hash_start(&ctx);
    for (int i = 0; i < 10; i++)
    {
        crypto_hash_append(&ctx, binary.data() + i * 4096, 4096);
    }
    vector<uint8_t> hash(HASH_OUTPUT_SIZE);
    crypto_hash_report(&ctx, hash.data());
    puthex(hash);

    crypto_hash_start(&ctx);
    crypto_hash_append(&ctx, binary.data(), binary.size());
    err_t rv = crypto_hash_verify(&ctx, hash.data());
    ASSERT_EQ(rv, ERR_OK);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(MBedTlsAbstraction, aead_cipher)
{
    crypto_aead_context_t enc, dec;
    vector<uint8_t> nonce(CRYPTO_AEAD_NONCE_SIZE),
        aad(32),
        plain(4096 * 10),
        decrypted(4096 * 10),
        cipher(CRYPTO_AEAD_CIPHERTEXT_SIZE(4096));
#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    crypto_aead_init(&enc);
    crypto_aead_peer(&enc, &dec);

    std::iota(plain.begin(), plain.end(), 0);
    std::iota(aad.begin(), aad.end(), 0);

    err_t ok;
    for (int i = 0; i < 10; i++)
    {
        crypto_aead_encrypt(&enc, aad.data(), aad.size(), plain.data() + i * 4096, 4096, cipher.data(), nonce.data());
        ok = crypto_aead_decrypt(&dec, aad.data(), aad.size(), cipher.data(), CRYPTO_AEAD_CIPHERTEXT_SIZE(4096), nonce.data(), decrypted.data() + i * 4096);
        ASSERT_EQ(ok, ERR_OK);
    }

    ASSERT_EQ(plain, decrypted);

    crypto_aead_free(&enc);
    crypto_aead_free(&dec);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(MBedTlsAbstraction, aead_cipher_key)
{
    crypto_aead_context_t enc, dec;
    vector<uint8_t> key(CRYPTO_AEAD_KEY_SIZE), key2(CRYPTO_AEAD_KEY_SIZE),
        nonce(CRYPTO_AEAD_NONCE_SIZE),
        aad(32),
        plain(4096),
        decrypted(4096),
        cipher(CRYPTO_AEAD_CIPHERTEXT_SIZE(4096));
#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif
    std::iota(plain.begin(), plain.end(), 0);
    std::iota(aad.begin(), aad.end(), 0);

    crypto_aead_init(&enc);
    crypto_aead_export(&enc, key.data());
    crypto_aead_import(&dec, key.data());
    crypto_aead_encrypt(&enc, aad.data(), aad.size(), plain.data(), plain.size(), cipher.data(), nonce.data());
    err_t ok = crypto_aead_decrypt(&dec, aad.data(), aad.size(), cipher.data(), CRYPTO_AEAD_CIPHERTEXT_SIZE(plain.size()), nonce.data(), decrypted.data());
    ASSERT_EQ(ok, ERR_OK);
    ASSERT_EQ(plain, decrypted);

    crypto_aead_export(&dec, key2.data());
    ASSERT_EQ(key, key2);

    crypto_aead_free(&enc);
    crypto_aead_free(&dec);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(MBedTlsAbstraction, key_exchange)
{
    crypto_dh_context_t A = {.step = CRYPTO_DH_NOT_STARTED}, B = {.step = CRYPTO_DH_NOT_STARTED};
    vector<uint8_t> A_pub(CRYPTO_DH_PUBKEY_SIZE), B_pub(CRYPTO_DH_PUBKEY_SIZE);
    std::printf("public key size: %zu B\n", A_pub.size());

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    crypto_dh_propose(&A, A_pub.data());
    crypto_dh_exchange_propose(&B, A_pub.data(), B_pub.data());
    crypto_dh_exchange(&A, B_pub.data());

    crypto_aead_context_t enc, dec;
    crypto_dh_derive_aead(&A, &enc);
    crypto_dh_derive_aead(&B, &dec);

    vector<uint8_t> enc_key(CRYPTO_AEAD_KEY_SIZE), dec_key(CRYPTO_AEAD_KEY_SIZE);
    crypto_aead_export(&enc, enc_key.data());
    crypto_aead_export(&dec, dec_key.data());

    ASSERT_EQ(enc_key, dec_key);

    crypto_aead_free(&enc);
    crypto_aead_free(&dec);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(MBedTlsAbstraction, key_exchange_memory_leak)
{
    crypto_dh_context_t A = {.step = CRYPTO_DH_NOT_STARTED}, B = {.step = CRYPTO_DH_NOT_STARTED};
    vector<uint8_t> A_pub(CRYPTO_DH_PUBKEY_SIZE), B_pub(CRYPTO_DH_PUBKEY_SIZE);

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    crypto_aead_context_t enc = {.has_key = 0}, dec = {.has_key = 0};
    int k = 100;
    while (k -- > 0)
    {
        crypto_dh_propose(&A, A_pub.data());
        crypto_dh_exchange_propose(&B, A_pub.data(), B_pub.data());
        crypto_dh_exchange(&A, B_pub.data());
        crypto_dh_derive_aead(&A, &enc);
        crypto_dh_derive_aead(&B, &dec);
        crypto_aead_free(&enc);
        crypto_aead_free(&dec);
    }

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}

TEST_F(MBedTlsAbstraction, digital_signature)
{
    crypto_ds_context_t A = CRYPTO_DS_CONTEXT_INIT,
                        B = CRYPTO_DS_CONTEXT_INIT;

#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    vector<uint8_t> message(1024), signature(CRYPTO_DS_SIGNATURE_SIZE);
    std::iota(message.begin(), message.end(), 0);

    char keypair[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIFu+gs1t0snvHh1OR0tbBLbYIFJKBYy7dcwraPJJYiBUoAoGCCqGSM49\n"
        "AwEHoUQDQgAElCWQ5N83+DKMkD0O5eHvQIq8UcPtSgauwK0qZZyxFRb1N128oAeZ\n"
        "7swgbvy45avpQvrHCf2VVFTvKC43J6uNgQ==\n"
        "-----END EC PRIVATE KEY-----\0";

    char pubkey[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElCWQ5N83+DKMkD0O5eHvQIq8UcPt\n"
        "SgauwK0qZZyxFRb1N128oAeZ7swgbvy45avpQvrHCf2VVFTvKC43J6uNgQ==\n"
        "-----END PUBLIC KEY-----\0";

    crypto_ds_import(&A, (const uint8_t *) keypair, sizeof(keypair));
    crypto_ds_import_pubkey(&B, (const uint8_t *) pubkey, sizeof(pubkey));

    size_t olen = 0;
    vector<uint8_t> ask(CRYPTO_DS_KEY_SIZE), apk(CRYPTO_DS_PUBKEY_SIZE), bpk(CRYPTO_DS_PUBKEY_SIZE);
    psa_call(psa_export_key, A.key, ask.data(), ask.size(), &olen);
    ASSERT_EQ(olen, ask.size());
    puthex(ask);
    psa_call(psa_export_public_key, A.key, apk.data(), apk.size(), &olen);
    ASSERT_EQ(olen, apk.size());
    puthex(apk);
    psa_call(psa_export_public_key, B.key, bpk.data(), bpk.size(), &olen);
    ASSERT_EQ(olen, bpk.size());
    puthex(bpk);
    ASSERT_EQ(apk, bpk);

    crypto_ds_sign(&A, message.data(), message.size(), signature.data());
    puthex(signature);
    err_t rv = crypto_ds_verify(&B, message.data(), message.size(), signature.data());
    ASSERT_EQ(rv, ERR_OK);

    crypto_ds_free(&A);
    crypto_ds_free(&B);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}
