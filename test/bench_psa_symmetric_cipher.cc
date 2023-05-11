#include <benchmark/benchmark.h>
#include <vector>
#include <gtest/gtest.h>
#include <utility>
#include <numeric>
#include <psa/crypto.h>
#include <mbedtls/memory_buffer_alloc.h>
using namespace std;

#include <abstraction.h>

static vector<unsigned char>
    data(1024),
    raw_key(32),
    ciphertext(1024 + 64),
    plaintext(1024);

static void DoSetup(const benchmark::State& state) {
    static bool initialized = false;
    if (!initialized) {
        crypto_init();
        std::iota(::data.begin(), ::data.end(), 0);
        initialized = true;
    }
}

static void DoTeardown(const benchmark::State& state) {
}

static void
BM_Warmup(benchmark::State& state)
{
    for (auto _ : state)
    {
    }
}

static void
BM_RngGen(benchmark::State& state)
{
    vector<unsigned char> key(32);
    for (auto _ : state)
    {
        psa_generate_random(key.data(), key.size());
    }
}

static void
BM_KeyGen(benchmark::State& state)
{
    psa_status_t status;
    psa_key_attributes_t kattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&kattr, PSA_ALG_CTR);
    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&kattr, 128);

    psa_key_handle_t key;
    status = psa_generate_key(&kattr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);
    status = psa_destroy_key(key);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_generate_key(&kattr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);
    status = psa_destroy_key(key);
    ASSERT_EQ(status, PSA_SUCCESS);

    for (auto _ : state)
    {
        psa_generate_key(&kattr, &key);
        psa_destroy_key(key);
    }
}

static void
    BM_KeyExport(benchmark::State& state)
{
    psa_status_t status;
    psa_key_attributes_t kattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&kattr, PSA_ALG_CTR);
    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&kattr, 128);

    psa_key_handle_t key;
    status = psa_generate_key(&kattr, &key);
    ASSERT_EQ(status, PSA_SUCCESS);

    size_t olen;
    status = psa_export_key(key, ::raw_key.data(), ::raw_key.size(), &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_LE(olen, ::raw_key.size());

    for (auto _ : state)
    {
        psa_export_key(key, ::raw_key.data(), ::raw_key.size(), &olen);
    }
}

static void
    BM_Aes128Ctr(benchmark::State& state)
{
    psa_status_t status;
    psa_key_attributes_t kattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_COPY);
    psa_set_key_algorithm(&kattr, PSA_ALG_CTR);
    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&kattr, 128);

    psa_key_handle_t kenc, kdec;
    status = psa_generate_key(&kattr, &kenc);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_copy_key(kenc, &kattr, &kdec);
    ASSERT_EQ(status, PSA_SUCCESS);

    size_t olen;
    status = psa_cipher_encrypt(
        kenc,
        PSA_ALG_CTR,
        ::data.data(),
        ::data.size(),
        ::ciphertext.data(),
        ::ciphertext.size(),
        &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_GT(olen, ::data.size());
    status = psa_cipher_decrypt(
        kdec,
        PSA_ALG_CTR,
        ::ciphertext.data(),
        olen,
        ::plaintext.data(),
        ::plaintext.size(),
        &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_EQ(olen, ::data.size());
    ASSERT_EQ(::plaintext, ::data);

    for (auto _ : state)
    {
        psa_cipher_encrypt(
            kenc,
            PSA_ALG_CTR,
            ::data.data(),
            ::data.size(),
            ::ciphertext.data(),
            ::ciphertext.size(),
            &olen);
        psa_cipher_decrypt(
            kdec,
            PSA_ALG_CTR,
            ::ciphertext.data(),
            olen,
            ::plaintext.data(),
            ::plaintext.size(),
            &olen);
    }

    status = psa_destroy_key(kenc);
    status = psa_destroy_key(kdec);
    ASSERT_EQ(status, PSA_SUCCESS);
}

static void
    BM_Aes128Gcm(benchmark::State& state)
{
    psa_status_t status;
    psa_key_attributes_t kattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_COPY);
    psa_set_key_algorithm(&kattr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM));
    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&kattr, 128);

    psa_key_handle_t kenc, kdec;
    status = psa_generate_key(&kattr, &kenc);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_copy_key(kenc, &kattr, &kdec);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> nonce(12);
    psa_generate_random(nonce.data(), nonce.size());

    vector<uint8_t> ad(8);
    std::iota(ad.begin(), ad.end(), 0);

    size_t olen;
    status = psa_aead_encrypt(
        kenc,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
        nonce.data(),
        nonce.size(),
        ad.data(),
        ad.size(),
        ::data.data(),
        ::data.size(),
        ::ciphertext.data(),
        ::ciphertext.size(),
        &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_GT(olen, ::data.size());
    status = psa_aead_decrypt(
        kdec,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
        nonce.data(),
        nonce.size(),
        ad.data(),
        ad.size(),
        ::ciphertext.data(),
        olen,
        ::plaintext.data(),
        ::plaintext.size(),
        &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_EQ(olen, ::data.size());
    ASSERT_EQ(::plaintext, ::data);

    for (auto _ : state)
    {
        psa_aead_encrypt(
            kenc,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
            nonce.data(),
            nonce.size(),
            ad.data(),
            ad.size(),
            ::data.data(),
            ::data.size(),
            ::ciphertext.data(),
            ::ciphertext.size(),
            &olen);
        psa_aead_decrypt(
            kdec,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_GCM),
            nonce.data(),
            nonce.size(),
            ad.data(),
            ad.size(),
            ::ciphertext.data(),
            olen,
            ::plaintext.data(),
            ::plaintext.size(),
            &olen);
    }

    status = psa_destroy_key(kenc);
    status = psa_destroy_key(kdec);
    ASSERT_EQ(status, PSA_SUCCESS);
}

static void
    BM_ChachaPoly(benchmark::State& state)
{
    psa_status_t status;
    psa_key_attributes_t kattr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_COPY);
    psa_set_key_algorithm(&kattr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305));
    psa_set_key_type(&kattr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&kattr, 256);

    psa_key_handle_t kenc, kdec;
    status = psa_generate_key(&kattr, &kenc);
    ASSERT_EQ(status, PSA_SUCCESS);

    status = psa_copy_key(kenc, &kattr, &kdec);
    ASSERT_EQ(status, PSA_SUCCESS);

    vector<uint8_t> nonce(12);
    psa_generate_random(nonce.data(), nonce.size());

    vector<uint8_t> ad(8);
    std::iota(ad.begin(), ad.end(), 0);

    size_t olen;
    status = psa_aead_encrypt(
        kenc,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
        nonce.data(),
        nonce.size(),
        ad.data(),
        ad.size(),
        ::data.data(),
        ::data.size(),
        ::ciphertext.data(),
        ::ciphertext.size(),
        &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_GT(olen, ::data.size());
    status = psa_aead_decrypt(
        kdec,
        PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
        nonce.data(),
        nonce.size(),
        ad.data(),
        ad.size(),
        ::ciphertext.data(),
        olen,
        ::plaintext.data(),
        ::plaintext.size(),
        &olen);
    ASSERT_EQ(status, PSA_SUCCESS);
    ASSERT_EQ(olen, ::data.size());
    ASSERT_EQ(::plaintext, ::data);

    for (auto _ : state)
    {
        psa_aead_encrypt(
            kenc,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            nonce.data(),
            nonce.size(),
            ad.data(),
            ad.size(),
            ::data.data(),
            ::data.size(),
            ::ciphertext.data(),
            ::ciphertext.size(),
            &olen);
        psa_aead_decrypt(
            kdec,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            nonce.data(),
            nonce.size(),
            ad.data(),
            ad.size(),
            ::ciphertext.data(),
            olen,
            ::plaintext.data(),
            ::plaintext.size(),
            &olen);
    }
    psa_destroy_key(kenc);
    psa_destroy_key(kdec);
}

BENCHMARK(BM_Warmup)->Iterations(10)->Setup(DoSetup);
BENCHMARK(BM_RngGen);
BENCHMARK(BM_KeyExport);
BENCHMARK(BM_KeyGen);
BENCHMARK(BM_Aes128Ctr);
BENCHMARK(BM_Aes128Gcm);
BENCHMARK(BM_ChachaPoly);

BENCHMARK_MAIN();
