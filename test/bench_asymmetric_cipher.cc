#include <benchmark/benchmark.h>
#include <numeric>
#include <vector>
#include <utility>

#include <enclave.h>

static std::vector<unsigned char> data(1024);
static std::vector<unsigned char> key(32);


static void DoSetup(const benchmark::State& state) {
    static bool initialized = false;
    if (!initialized) {
        crypto_init();
        std::iota(data.begin(), data.end(), 0);
        std::iota(key.begin(), key.end(), 0);
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

crypto_ds_context_t sender, receiver;
crypto_ds_public_key_t public_key;

static void
    BM_ECDSA(benchmark::State& state)
{
    crypto_ds_signature_t sig;
    int is_match = 0;
    crypto_ds_init(&sender);
    crypto_ds_gen_keypair(&sender);

    crypto_ds_init(&receiver);
    crypto_ds_export_public_key(&sender, &public_key);
    crypto_ds_import_public_key(&receiver, &public_key);

    for (auto _ : state)
    {
        crypto_sign(&sender, data.data(), data.size(), &sig);
        crypto_verify(&receiver, data.data(), data.size(), &sig, &is_match);
    }
    crypto_ds_free(&sender);
    crypto_ds_free(&receiver);
}

crypto_sc_mac_context_t writer, reader;
static std::vector<unsigned char> buffer(1024 + 16);

static void
    BM_ECDSA_MAC(benchmark::State& state)
{
    crypto_ds_signature_t sig;
    int is_match = 0;
    crypto_ds_init(&sender);
    crypto_ds_gen_keypair(&sender);
    crypto_sc_mac_init(&writer, key.data(), key.size(), 1);

    crypto_ds_init(&receiver);
    crypto_ds_export_public_key(&sender, &public_key);
    crypto_ds_import_public_key(&receiver, &public_key);
    crypto_sc_mac_init(&reader, key.data(), key.size(), 0);

    size_t olen, len;
    for (auto _ : state)
    {
        crypto_sc_mac_encrypt(&writer, data.data(), data.size(), buffer.data(), &olen);
        crypto_sign(&sender, buffer.data() + 1024, 16, &sig);

        crypto_sc_mac_decrypt(&reader, buffer.data(), olen, data.data(), &len);
        crypto_verify(&receiver, buffer.data() + 1024, 16, &sig, &is_match);
    }
    crypto_ds_free(&sender);
    crypto_ds_free(&receiver);
}

BENCHMARK(BM_Warmup)->Iterations(10)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_ECDSA)->Setup(DoSetup)->Teardown(DoTeardown);
BENCHMARK(BM_ECDSA_MAC)->Setup(DoSetup)->Teardown(DoTeardown);

BENCHMARK_MAIN();
