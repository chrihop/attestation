#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <numeric>
#include <vector>
#include <utility>
using namespace std;

#include <enclave.h>

static uint8_t key[32];
static uint8_t msg[4096];
static uint8_t ciphertext[4096 + 16];
static uint8_t output[4096];

static void DoSetup(const benchmark::State& state) {
    static bool initialized = false;
    if (!initialized) {
        crypto_init();
        std::iota(key, key + 32, 0);
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
BM_ChachaPoly(benchmark::State& state)
{
    crypto_sc_mac_context_t writer, reader;
    crypto_sc_mac_init(&writer, key, 32, 1);
    crypto_sc_mac_init(&reader, key, 32, 0);

    size_t len, olen;
    for (auto _ : state)
    {
        crypto_sc_mac_encrypt(&writer, msg, 4096, ciphertext, &len);
        crypto_sc_mac_decrypt(&reader, ciphertext, len, output, &olen);
    }
}

static void
BM_ChachaPoly_RAC(benchmark::State& state)
{
    crypto_rac_context_t writer, reader;
    crypto_rac_init(&writer, key, 32);
    crypto_rac_init(&reader, key, 32);

    size_t len, olen, nonce_len;
    uint8_t nonce[12];
    for (auto _ : state)
    {
        crypto_rac_encrypt(&writer, msg, 4096, ciphertext, &len, nonce, &nonce_len);
        crypto_rac_decrypt(&reader, nonce, nonce_len, ciphertext, len, output, &olen);
    }
}

static void
BM_CamelliaCBC(benchmark::State& state)
{
    mbedtls_camellia_context writer, reader;
    mbedtls_camellia_init(&writer);
    mbedtls_camellia_init(&reader);
    mbedtls_camellia_setkey_enc(&writer, key, 256);
    mbedtls_camellia_setkey_dec(&reader, key, 256);

    uint8_t iv[16];
    for (auto _ : state)
    {
        crypto_rng(iv, 16);
        mbedtls_camellia_crypt_cbc(&writer, MBEDTLS_CAMELLIA_ENCRYPT, 4096, iv, msg, ciphertext);
        mbedtls_camellia_crypt_cbc(&reader, MBEDTLS_CAMELLIA_DECRYPT, 4096, iv, ciphertext, output);
    }
}

static void
BM_CamelliaCFB(benchmark::State& state)
{
    mbedtls_camellia_context writer, reader;
    mbedtls_camellia_init(&writer);
    mbedtls_camellia_init(&reader);
    mbedtls_camellia_setkey_enc(&writer, key, 256);
    mbedtls_camellia_setkey_dec(&reader, key, 256);

    uint8_t iv[16];
    for (auto _ : state)
    {
        crypto_rng(iv, 16);
        size_t iv_off = 0;
        mbedtls_camellia_crypt_cfb128(&writer, MBEDTLS_CAMELLIA_ENCRYPT, 4096, &iv_off, iv, msg, ciphertext);
        mbedtls_camellia_crypt_cfb128(&reader, MBEDTLS_CAMELLIA_DECRYPT, 4096, &iv_off, iv, ciphertext, output);
    }
}

static void
    BM_CamelliaCTR(benchmark::State& state)
{
    mbedtls_camellia_context writer, reader;
    mbedtls_camellia_init(&writer);
    mbedtls_camellia_init(&reader);
    mbedtls_camellia_setkey_enc(&writer, key, 256);
    mbedtls_camellia_setkey_enc(&reader, key, 256);

    size_t nc_off;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    for (auto _ : state)
    {
        nc_off = 0;
        crypto_rng(nonce_counter, 16);
        mbedtls_camellia_crypt_ctr(&writer, 4096, &nc_off, nonce_counter, stream_block, msg, ciphertext);
        mbedtls_camellia_crypt_ctr(&reader, 4096, &nc_off, nonce_counter, stream_block, ciphertext, output);
    }
}

static void
    BM_AES256CBC(benchmark::State& state)
{
    int rv;
    mbedtls_aes_context writer, reader;
    mbedtls_aes_init(&writer);
    mbedtls_aes_init(&reader);
    rv = mbedtls_aes_setkey_enc(&writer, key, 256);
    rv = mbedtls_aes_setkey_dec(&reader, key, 256);

    uint8_t iv[16];
    for (auto _ : state)
    {
        crypto_rng(iv, 16);
        rv = mbedtls_aes_crypt_cbc(&writer, MBEDTLS_AES_ENCRYPT, 4096, iv, msg, ciphertext);
        rv = mbedtls_aes_crypt_cbc(&reader, MBEDTLS_AES_DECRYPT, 4096, iv, ciphertext, output);
    }
    benchmark::DoNotOptimize(rv);
}

static void
    BM_AES128CFB(benchmark::State& state)
{
    int rv;
    mbedtls_aes_context writer, reader;
    mbedtls_aes_init(&writer);
    mbedtls_aes_init(&reader);
    rv = mbedtls_aes_setkey_enc(&writer, key, 256);
    rv = mbedtls_aes_setkey_dec(&reader, key, 256);

    uint8_t iv[16];
    for (auto _ : state)
    {
        crypto_rng(iv, 16);
        size_t iv_off = 0;
        rv = mbedtls_aes_crypt_cfb128(&writer, MBEDTLS_AES_ENCRYPT, 4096, &iv_off, iv, msg, ciphertext);
        rv = mbedtls_aes_crypt_cfb128(&reader, MBEDTLS_AES_DECRYPT, 4096, &iv_off, iv, ciphertext, output);
    }
    benchmark::DoNotOptimize(rv);
}

BENCHMARK(BM_Warmup)->Iterations(10)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_ChachaPoly)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_ChachaPoly_RAC)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_CamelliaCBC)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_CamelliaCFB)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_CamelliaCTR)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_AES256CBC)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_AES128CFB)->Setup(DoSetup)->Teardown(DoTeardown);

BENCHMARK_MAIN();
