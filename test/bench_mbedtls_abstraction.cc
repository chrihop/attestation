#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <numeric>
#include <psa/crypto.h>
#include <utility>
#include <vector>
using namespace std;

#include <abstraction.h>

static vector<uint8_t> data(1024);

static void
DoSetup(const benchmark::State& state)
{
    static bool initialized = false;
    if (!initialized)
    {
        crypto_init();
        std::iota(::data.begin(), ::data.end(), 0);
        initialized = true;
    }
}

static void
DoTeardown(const benchmark::State& state)
{
}

static void
BM_Warmup(benchmark::State& state)
{
    for (auto _ : state)
    {
    }
}

static void
BM_SecureHash(benchmark::State& state)
{
    vector<unsigned char> data(1024);
    std::iota(data.begin(), data.end(), 0);
    crypto_hash_context_t ctx;
    vector<uint8_t>                 hash(CRYPTO_HASH_SIZE);
    for (auto _ : state)
    {
        crypto_hash_start(&ctx);
        crypto_hash_append(&ctx, data.data(), data.size());
        crypto_hash_report(&ctx, hash.data());
    }
}

static void
BM_PsaHash(benchmark::State& state)
{
    vector<unsigned char> data(1024);
    std::iota(data.begin(), data.end(), 0);
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    vector<uint8_t>                 hash(CRYPTO_HASH_SIZE);
    size_t               olen;
    for (auto _ : state)
    {
        psa_call(psa_hash_setup, &op, PSA_ALG_SHA_256);
        psa_call(psa_hash_update, &op, data.data(), data.size());
        psa_call(psa_hash_finish, &op, hash.data(), 32, &olen);
    }
}

static void
BM_AEAD_cipher(benchmark::State& state)
{
    vector<uint8_t> nonce(CRYPTO_AEAD_NONCE_SIZE);
    vector<uint8_t> ad(16);
    std::iota(ad.begin(), ad.end(), 0);
    vector<uint8_t> ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(::data.size()));
    crypto_aead_context_t enc = CRYPTO_AEAD_CONTEXT_INIT, dec = CRYPTO_AEAD_CONTEXT_INIT;
    crypto_aead_init(&enc);
    crypto_aead_peer(&enc, &dec);
    err_t ok;
    for (auto _ : state)
    {
        crypto_aead_encrypt(&enc, ad.data(), ad.size(), ::data.data(),
            ::data.size(), ciphertext.data(), nonce.data());
        ok = crypto_aead_decrypt(&dec, ad.data(), ad.size(), ciphertext.data(),
            ciphertext.size(), nonce.data(), ::data.data());
    }
    benchmark::DoNotOptimize(ok);
}

static void
BM_AEAD_cipher_psa(benchmark::State& state)
{
    vector<uint8_t> nonce(CRYPTO_AEAD_NONCE_SIZE);
    vector<uint8_t> ad(16);
    std::iota(ad.begin(), ad.end(), 0);
    vector<uint8_t>      ciphertext(CRYPTO_AEAD_CIPHERTEXT_SIZE(::data.size()));

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(
        &attr, PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305));
    psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attr, 256);

    psa_key_id_t key;
    psa_call(psa_generate_key, &attr, &key);

    psa_status_t ok;
    size_t olen;
    for (auto _ : state)
    {
        psa_call(psa_generate_random, nonce.data(), nonce.size());
        psa_call(psa_aead_encrypt, key,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            nonce.data(), nonce.size(), ad.data(), ad.size(), ::data.data(),
            ::data.size(), ciphertext.data(), ciphertext.size(),
            &olen);
        psa_call(psa_aead_decrypt, key,
            PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CHACHA20_POLY1305),
            nonce.data(), nonce.size(), ad.data(), ad.size(), ciphertext.data(),
            ciphertext.size(), ::data.data(), ::data.size(), &olen);
    }
    benchmark::DoNotOptimize(ok);
}

static void
BM_key_exchange(benchmark::State & state)
{
    crypto_dh_context_t A = CRYPTO_DH_CONTEXT_INIT, B = CRYPTO_DH_CONTEXT_INIT;

    vector<uint8_t> A_pubkey(CRYPTO_DH_PUBKEY_SIZE), B_pubkey(CRYPTO_DH_PUBKEY_SIZE);

    for (auto _ : state)
    {
        crypto_dh_propose(&A, A_pubkey.data());
        crypto_dh_exchange_propose(&B, A_pubkey.data(), B_pubkey.data());
        crypto_dh_exchange(&A, B_pubkey.data());
        crypto_dh_free(&A);
        crypto_dh_free(&B);
    }
}

static void
BM_psa_key_exchange(benchmark::State & state)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);

    psa_key_id_t key;

    psa_key_attributes_t attr2 = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(
        &attr2, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr2, PSA_ALG_ECDH);
    psa_set_key_type(&attr2, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr2, 255);

    psa_key_id_t key2;

    psa_key_derivation_operation_t op1 = PSA_KEY_DERIVATION_OPERATION_INIT,
                                    op2 = PSA_KEY_DERIVATION_OPERATION_INIT;

    vector<uint8_t> info(16);
    std::iota(info.begin(), info.end(), 0);

    psa_key_handle_t sk1, sk2;
    psa_key_attributes_t sk_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&sk_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&sk_attr, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&sk_attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&sk_attr, 256);

    vector<uint8_t> pubkey(CRYPTO_DH_PUBKEY_SIZE), pubkey2(CRYPTO_DH_PUBKEY_SIZE);
    size_t olen;
    for (auto _ : state)
    {
        psa_call(psa_generate_key, &attr, &key);
        psa_call(psa_generate_key, &attr2, &key2);

        psa_call(psa_key_derivation_setup, &op1, PSA_ALG_KEY_AGREEMENT(
                PSA_ALG_ECDH, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)));
        psa_call(psa_key_derivation_setup, &op2, PSA_ALG_KEY_AGREEMENT(
                PSA_ALG_ECDH, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)));

        psa_call(psa_export_public_key, key, pubkey.data(), pubkey.size(), &olen);
        psa_call(psa_export_public_key, key2, pubkey2.data(), pubkey2.size(), &olen);
        psa_call(psa_key_derivation_key_agreement,
            &op1, PSA_KEY_DERIVATION_INPUT_SECRET, key, pubkey2.data(), pubkey2.size());
        psa_call(psa_key_derivation_key_agreement,
            &op2, PSA_KEY_DERIVATION_INPUT_SECRET, key2, pubkey.data(), pubkey.size());
        psa_call(psa_key_derivation_input_bytes,
            &op1, PSA_KEY_DERIVATION_INPUT_INFO, info.data(), info.size());
        psa_call(psa_key_derivation_input_bytes,
            &op2, PSA_KEY_DERIVATION_INPUT_INFO, info.data(), info.size());
        psa_call(psa_key_derivation_output_key,
            &sk_attr, &op1, &sk1);
        psa_call(psa_key_derivation_output_key,
            &sk_attr, &op2, &sk2);
        psa_call(psa_key_derivation_abort, &op1);
        psa_call(psa_key_derivation_abort, &op2);
        psa_call(psa_destroy_key, sk1);
        psa_call(psa_destroy_key, sk2);

        psa_call(psa_destroy_key, key);
        psa_call(psa_destroy_key, key2);
    }
}

static void BM_digital_signature(benchmark::State & state)
{
    crypto_ds_context_t A = CRYPTO_DS_CONTEXT_INIT, B = CRYPTO_DS_CONTEXT_INIT;

    uint8_t keypair[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIFu+gs1t0snvHh1OR0tbBLbYIFJKBYy7dcwraPJJYiBUoAoGCCqGSM49\n"
        "AwEHoUQDQgAElCWQ5N83+DKMkD0O5eHvQIq8UcPtSgauwK0qZZyxFRb1N128oAeZ\n"
        "7swgbvy45avpQvrHCf2VVFTvKC43J6uNgQ==\n"
        "-----END EC PRIVATE KEY-----\0";

    uint8_t pubkey[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElCWQ5N83+DKMkD0O5eHvQIq8UcPt\n"
        "SgauwK0qZZyxFRb1N128oAeZ7swgbvy45avpQvrHCf2VVFTvKC43J6uNgQ==\n"
        "-----END PUBLIC KEY-----\0";

    crypto_ds_import(&A, keypair, sizeof(keypair));
    crypto_ds_import_pubkey(&B, pubkey, sizeof(pubkey));
    vector<uint8_t> msg(1024), sig(CRYPTO_DS_SIGNATURE_SIZE);
    std::iota(msg.begin(), msg.end(), 0);

    for (auto _ : state)
    {
        crypto_ds_sign(&A, msg.data(), msg.size(), sig.data());
        crypto_ds_verify(&B, msg.data(), msg.size(), sig.data());
    }
}

static void BM_psa_ecdsa(benchmark::State & state)
{
    psa_key_handle_t key;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, 256);

    psa_key_handle_t pubkey;
    psa_key_attributes_t pubkey_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&pubkey_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&pubkey_attr, 256);

    psa_call(psa_generate_key, &key_attr, &key);
    vector<uint8_t> msg(1024), sig(CRYPTO_DS_SIGNATURE_SIZE), pubkey_buf(CRYPTO_DS_PUBKEY_SIZE);
    size_t olen;
    psa_call(psa_export_public_key, key, pubkey_buf.data(), pubkey_buf.size(), &olen);
    psa_call(psa_import_key, &pubkey_attr, pubkey_buf.data(), olen, &pubkey);

    std::iota(msg.begin(), msg.end(), 0);

    for (auto _ : state)
    {
        psa_call(psa_sign_message, key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg.data(), msg.size(), sig.data(), sig.size(), &olen);
        psa_call(psa_verify_message, pubkey, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg.data(), msg.size(), sig.data(), olen);
    }
    psa_call(psa_destroy_key, key);
    psa_call(psa_destroy_key, pubkey);
}

BENCHMARK(BM_Warmup)->Iterations(10)->Setup(DoSetup);
BENCHMARK(BM_SecureHash);
BENCHMARK(BM_PsaHash);
BENCHMARK(BM_AEAD_cipher);
BENCHMARK(BM_AEAD_cipher_psa);
BENCHMARK(BM_key_exchange);
BENCHMARK(BM_psa_key_exchange);
BENCHMARK(BM_digital_signature);
BENCHMARK(BM_psa_ecdsa);

BENCHMARK_MAIN();
