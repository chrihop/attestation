#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <elfio/elfio.hpp>
#include <numeric>
#include <vector>
using namespace std;

#include <enclave_platform.h>

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

class EnclavePlatformTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static bool init = false;
        if (init)
            return;
        crypto_init();
        enclave_platform_init();
        init = true;
    }
    void TearDown() override
    {
    }
};

uint8_t dsk_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHQCAQEEIKYTeJPhkbUOh1I98rRPmkVXbo4Ia8l1E6GARlZkljdfoAcGBSuBBAAK\n"
    "oUQDQgAEtraDYUMjm0hWpiiqjdjLVB/AJVUhXwMDjg87U76r2Efzn33bxHapCsXD\n"
    "ZXNzrPkjpNmkBRcANAPhOTrG4UPq3w==\n"
    "-----END EC PRIVATE KEY-----\0";


uint8_t dvk_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEtraDYUMjm0hWpiiqjdjLVB/AJVUhXwMD\n"
    "jg87U76r2Efzn33bxHapCsXDZXNzrPkjpNmkBRcANAPhOTrG4UPq3w==\n"
    "-----END PUBLIC KEY-----\0";


TEST_F(EnclavePlatformTest, secure_loader_hash_sanity)
{
    vector<uint8_t> binary(1024 * 20);
    std::iota(binary.begin(), binary.end(), 0);
    err_t err;

    vector<uint8_t>
        hash(CRYPTO_HASH_SIZE),
        signature(CRYPTO_DS_SIGNATURE_SIZE);

    crypto_hash_context_t hash_ctx = CRYPTO_HASH_CONTEXT_INIT;
    crypto_hash_start(&hash_ctx);
    for (int i = 0; i < 20; i++)
    {
        crypto_hash_append(&hash_ctx, binary.data() + i * 1024, 1024);
    }
    crypto_hash_report(&hash_ctx, hash.data());
    puthex(hash);

    crypto_hash_start(&hash_ctx);
    crypto_hash_append(&hash_ctx, binary.data(), binary.size());
    err = crypto_hash_verify(&hash_ctx, hash.data());
    ASSERT_EQ(err, ERR_OK);
}

static void memory_dump(const void * addr, size_t size, uintptr_t offset = 0)
{
    printf("-- %lu B --\n", size);
    for (int i = 1; i <= size; i++)
    {
        if ((i % 16) == 1)
        {
            printf("%08lx: ", offset + i - 1);
        }

        printf("%02x", ((uint8_t *)addr)[i - 1]);
        if (i != 0 && (i % 16) == 0)
        {
            printf("\n");
        }
        else if (i != 0 && (i % 8) == 0)
        {
            printf("    ");
        }
        else if (i != 0 && (i % 4) == 0)
        {
            printf("  ");
        }
        else
        {
            printf(" ");
        }
    }
}

TEST_F(EnclavePlatformTest, secure_loader_key_sanity)
{
    err_t err;
    vector<uint8_t> dvk1(CRYPTO_DS_PUBKEY_SIZE),
        dvk2(CRYPTO_DS_PUBKEY_SIZE);
    crypto_pki_context_t pki_ctx = CRYPTO_PKI_CONTEXT_INIT;
    crypto_ds_import(&pki_ctx.ds, dsk_pem, sizeof(dsk_pem));
    crypto_ds_export_pubkey(&pki_ctx.ds, dvk1.data());
    puthex(dvk1);

    crypto_pki_endorse(crypto_pki_root(), &pki_ctx);

    crypto_ds_context_t ds_ctx = CRYPTO_DS_CONTEXT_INIT;
    crypto_ds_import_pubkey(&ds_ctx, dvk_pem, sizeof(dvk_pem));
    crypto_ds_export_pubkey(&ds_ctx, dvk2.data());
    puthex(dvk2);
    ASSERT_EQ(dvk1, dvk2);

    err = crypto_ds_verify(&crypto_pki_root()->ds, dvk2.data(), dvk2.size(),
        pki_ctx.endorsement);
    ASSERT_EQ(err, ERR_OK);
}

static pair<vector<uint8_t>, vector<uint8_t>>
    secure_sign(const vector<uint8_t> & binary)
{
    err_t err;
    vector<uint8_t>
        hash(CRYPTO_HASH_SIZE),
        signature(CRYPTO_DS_SIGNATURE_SIZE),
        cert(CRYPTO_DS_SIGNATURE_SIZE);

    crypto_hash_context_t hash_ctx = CRYPTO_HASH_CONTEXT_INIT;
    crypto_hash_start(&hash_ctx);
    crypto_hash_append(&hash_ctx, binary.data(), binary.size());
    crypto_hash_report(&hash_ctx, hash.data());
    puthex(hash);

    crypto_pki_context_t pki_ctx = CRYPTO_PKI_CONTEXT_INIT;
    crypto_ds_import(&pki_ctx.ds, dsk_pem, sizeof(dsk_pem));
    crypto_pki_endorse(crypto_pki_root(), &pki_ctx);

    crypto_ds_sign(&pki_ctx.ds, hash.data(), hash.size(),
        signature.data());
    puthex(signature);

    return {signature, vector<uint8_t>(pki_ctx.endorsement,
                            pki_ctx.endorsement + CRYPTO_DS_SIGNATURE_SIZE)};
}

TEST_F(EnclavePlatformTest, secure_loader)
{
    vector<uint8_t> binary(1024 * 20);
    std::iota(binary.begin(), binary.end(), 0);

    auto [signature, cert] = secure_sign(binary);
    puthex(signature);
    puthex(cert);

    err_t err;
    enclave_node_t * node = enclave_node_at(0);
    enclave_node_load_start(node);

    for (int i = 0; i < 20; i++)
    {
        enclave_node_load_chunk(node, binary.data() + i * 1024, 1024);
    }

    err = enclave_node_load_verify(
        node, signature.data(), cert.data(), dvk_pem, sizeof(dvk_pem));

    puthex_n(node->hash, CRYPTO_HASH_SIZE);

    ASSERT_EQ(err, ERR_OK);
}

using namespace ELFIO;

static pair<size_t, size_t>
    get_bss(const elfio & reader)
{
    Elf_Half sects = reader.sections.size();
    for (int i = 0; i < sects; i++)
    {
        section * s = reader.sections[i];
        if (s->get_type() == SHT_NOBITS)
        {
            return {s->get_address(), s->get_size()};
        }
    }
    return {0, 0};
}

static pair<uintptr_t, size_t>
    get_section(const elfio & reader, string & name)
{
    Elf_Half sects = reader.sections.size();
    for (int i = 0; i < sects; i++)
    {
        section * s = reader.sections[i];
        if (s->get_name() == name)
        {
            return {s->get_offset(), s->get_size()};
        }
    }
    return {0, 0};
}

template<typename T> inline T
round_up(T a, T n)
{
    return a + (n - a % n);
};

template<typename T> inline T
round_down(T a, T n)
{
    return a - (a % n);
};


vector<uint8_t> load_file(const char * path)
{
    std::ifstream file(path, std::ios::binary);
    file.unsetf(std::ios::skipws);

    std::streampos fileSize;
    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    vector<uint8_t> buf;
    buf.reserve(fileSize);

    buf.insert(buf.begin(),
        std::istream_iterator<uint8_t>(file),
        std::istream_iterator<uint8_t>());
    file.close();
    return buf;
}

static void
load_segments(const elfio & reader, vector<uint8_t> & binary, enclave_node_t * node)
{
    Elf_Half segs = reader.segments.size();
    auto [bss_va, bss_size] = get_bss(reader);
    for (int i = 0; i < segs; i++)
    {
        segment * s = reader.segments[i];
        if (s->get_type() != PT_LOAD)
        {
            continue;
        }
        size_t fa = s->get_offset();
        size_t va = s->get_virtual_address();
        size_t fz = s->get_file_size();
        size_t vz = s->get_memory_size();
        size_t zva = va + fz;
        size_t eva = round_up(va + vz, 4096lu);
        size_t len = 0, inc = 0;
        vector<uint8_t> page(4096, 0);
        while (va < zva)
        {
            va += inc;
            fa += inc;
            std::fill(page.begin(), page.end(), 0);
            if (va >= eva)
            {
                break;
            }
            if (bss_va <= va && va + 4096lu <= bss_va + bss_size)
            {
                inc = 4096lu;
                continue;
            }
            if (va % 4096lu != 0)
            {
                len = min(4096lu - va % 4096lu, zva - va);
                std::copy(
                    binary.begin() + fa,
                    binary.begin() + fa + len,
                    page.begin() + va % 4096lu);
                inc = 4096lu - va % 4096lu;
            }
            else if (va < round_down(zva, 4096lu))
            {
                len = 4096lu;
                std::copy(
                    binary.begin() + fa,
                    binary.begin() + fa + len,
                    page.begin());
                inc = 4096lu;
            }
            else if (va < zva && fz > 0)
            {
                len = zva - va;
                std::copy(
                    binary.begin() + fa,
                    binary.begin() + fa + len,
                    page.begin());
                for (int i = len; i < 4096lu; i++)
                {
                    ASSERT_EQ(page[i], 0);
                }

                inc = 4096lu;
            }
            else
            {
                inc = 4096lu;
            }
#define VERBOSE 0
#if VERBOSE >= 1
            crypto_hash_context_t ctx = CRYPTO_HASH_CONTEXT_INIT;
            vector<uint8_t> hash(CRYPTO_HASH_SIZE);
            crypto_hash_start(&ctx);
            crypto_hash_append(&ctx, page.data(), 4096lu);
            crypto_hash_report(&ctx, hash.data());
            printf("%08lx %08lx: ", va, len);
            puthex(hash);
#endif

#if VERBOSE == 2
            memory_dump(page.data(), 4096lu, va);
#endif
            enclave_node_load_chunk(node, page.data(), 4096lu);
        }
    }
}

static section * find_section(const string name, const elfio & reader)
{
    Elf_Half sects = reader.sections.size();
    for (int i = 0; i < sects; i++)
    {
        section * s = reader.sections[i];
        if (s->get_name() == name)
        {
            return s;
        }
    }
    return nullptr;
}

TEST_F(EnclavePlatformTest, elfio)
{
    elfio reader;
    bool  rv;

    rv = reader.load("sample_enclave_user.signed");
    ASSERT_TRUE(rv);
}

TEST_F(EnclavePlatformTest, secure_loader_elf_file_sanity)
{
    elfio           reader;

    bool            rv;
    const char*     path   = "sample_enclave_user.signed";
    vector<uint8_t> binary = load_file(path);
    rv                     = reader.load(path);
    ASSERT_TRUE(rv);

    section* s_dvk = find_section(".enclave.public_key", reader);
    ASSERT_NE(s_dvk, nullptr);
    section* s_dvk_sig = find_section(".enclave.pubkey_sig", reader);
    ASSERT_NE(s_dvk_sig, nullptr);
    section* s_sig = find_section(".enclave.binary_sig", reader);
    ASSERT_NE(s_sig, nullptr);

    vector<uint8_t> dvk(CRYPTO_DS_PUBKEY_SIZE);
    puthex_n(s_dvk_sig->get_data(), s_dvk_sig->get_size());
    puthex_n(s_sig->get_data(), s_sig->get_size());

    ASSERT_EQ(s_dvk_sig->get_size(), CRYPTO_DS_SIGNATURE_SIZE);
    ASSERT_EQ(s_sig->get_size(), CRYPTO_DS_SIGNATURE_SIZE);

    crypto_ds_context_t ds = CRYPTO_DS_CONTEXT_INIT;
    size_t olen;
    crypto_ds_import_pubkey(
        &ds, (const uint8_t*)s_dvk->get_data(), s_dvk->get_size());
    psa_call(psa_export_public_key, ds.key, dvk.data(), dvk.size(), &olen);
    ASSERT_EQ(olen, dvk.size());
    puthex(dvk);

    enclave_node_t * node = enclave_node_at(0);
    enclave_node_load_start(node);
    load_segments(reader, binary, node);
    vector<uint8_t> hash(CRYPTO_HASH_SIZE);
    crypto_hash_report(&node->loader, hash.data());
    puthex(hash);

    crypto_ds_free(&ds);
}

TEST_F(EnclavePlatformTest, secure_loader_elf_file)
{
    elfio reader;

    bool rv;
    const char * path = "sample_enclave_user.signed";
    vector<uint8_t> binary = load_file(path);
    rv = reader.load( path );
    ASSERT_TRUE(rv);

    std::printf("%d-bit %s endian\n",
        reader.get_class() == ELFCLASS32 ? 32 : 64,
        reader.get_encoding() == ELFDATA2LSB ? "little" : "big");

    enclave_node_t * node = enclave_node_at(0);
    enclave_node_load_start(node);

    Elf_Half sects = reader.sections.size();
    for (int i = 0; i < sects; i++)
    {
        section * s = reader.sections[i];
        printf("[%2d] %-20s %16lx - %16lx -> %16lx - %16lx\n",
            i, s->get_name().c_str(),
            s->get_offset(), s->get_offset() + s->get_size(),
            s->get_address(), s->get_address() + s->get_size());
    }

    auto [bss_addr, bss_size] = get_bss(reader);
    printf("bss: %lx - %lx\n", bss_addr, bss_addr + bss_size);
    ASSERT_GT(bss_size, 0);
    Elf_Half segs = reader.segments.size();
    for (int i = 0; i < segs; i++)
    {
        segment * s = reader.segments[i];
        printf("[%2d] %-20s %16lx - %16lx -> %16lx - %16lx\n",
            i, s->get_type() == PT_LOAD ? "PT_LOAD" : "PT_OTHER",
            s->get_offset(), s->get_offset() + s->get_file_size(),
            s->get_virtual_address(), s->get_virtual_address() + s->get_memory_size());
    }

    load_segments(reader, binary, node);
    section * s_dvk = find_section(".enclave.public_key", reader);
    ASSERT_NE(s_dvk, nullptr);
    section * s_dvk_sig = find_section(".enclave.pubkey_sig", reader);
    ASSERT_NE(s_dvk_sig, nullptr);
    section * s_sig = find_section(".enclave.binary_sig", reader);
    ASSERT_NE(s_sig, nullptr);

    err_t err;
    ASSERT_EQ(s_sig->get_size(), CRYPTO_DS_SIGNATURE_SIZE);
    ASSERT_EQ(s_dvk_sig->get_size(), CRYPTO_DS_SIGNATURE_SIZE);
    err = enclave_node_load_verify(
        node,
        (const uint8_t *) s_sig->get_data(),
        (const uint8_t *) s_dvk_sig->get_data(),
        (const uint8_t *) s_dvk->get_data(), s_dvk->get_size()
    );
    ASSERT_EQ(err, ERR_OK);
}

TEST_F(EnclavePlatformTest, secure_loader_elf_trust)
{
    elfio       reader;

    bool        rv;
    const char* path = "sample_enclave_user.signed";
    rv               = reader.load(path);
    ASSERT_TRUE(rv);

    enclave_node_t* node = enclave_node_at(0);

    section*        s_slots = find_section(".enclave.trust", reader);
    ASSERT_NE(s_slots, nullptr);

    section* s_slots_sig = find_section(".enclave.trust_sig", reader);
    ASSERT_NE(s_slots_sig, nullptr);

    section* s_dvk = find_section(".enclave.public_key", reader);
    ASSERT_NE(s_dvk, nullptr);

    err_t err = enclave_node_trust_slots_verify(node,
        (const uint8_t*)s_slots->get_data(),
        (const uint8_t*)s_slots_sig->get_data(),
        (const uint8_t*)s_dvk->get_data(), s_dvk->get_size());
    ASSERT_EQ(err, ERR_OK);
}

TEST_F(EnclavePlatformTest, secure_loader_memory_leak)
{
#if defined (MBEDTLS_MEMORY_DEBUG)
    size_t used_before, blocks_before, used_after, blocks_after;
    mbedtls_memory_buffer_alloc_cur_get(&used_before, &blocks_before);
#endif

    elfio           reader;

    bool            rv;
    const char*     path   = "sample_enclave_user.signed";
    vector<uint8_t> binary = load_file(path);
    rv                     = reader.load(path);
    ASSERT_TRUE(rv);

    enclave_node_t* node = enclave_node_at(0);

    section* s_dvk = find_section(".enclave.public_key", reader);
    ASSERT_NE(s_dvk, nullptr);
    section* s_dvk_sig = find_section(".enclave.pubkey_sig", reader);
    ASSERT_NE(s_dvk_sig, nullptr);
    ASSERT_EQ(s_dvk_sig->get_size(), CRYPTO_DS_SIGNATURE_SIZE);
    section* s_sig = find_section(".enclave.binary_sig", reader);
    ASSERT_NE(s_sig, nullptr);
    ASSERT_EQ(s_sig->get_size(), CRYPTO_DS_SIGNATURE_SIZE);

    vector<uint8_t> dvk(CRYPTO_DS_PUBKEY_SIZE);

    err_t err;
    enclave_node_load_start(node);
    load_segments(reader, binary, node);
    err = enclave_node_load_verify(
        node,
        (const uint8_t*)s_sig->get_data(),
        (const uint8_t*)s_dvk_sig->get_data(),
        (const uint8_t*)s_dvk->get_data(), s_dvk->get_size());
    ASSERT_EQ(err, ERR_OK);

    section*        s_slots = find_section(".enclave.trust", reader);
    ASSERT_NE(s_slots, nullptr);

    section* s_slots_sig = find_section(".enclave.trust_sig", reader);
    ASSERT_NE(s_slots_sig, nullptr);

    err = enclave_node_trust_slots_verify(node,
        (const uint8_t*)s_slots->get_data(),
        (const uint8_t*)s_slots_sig->get_data(),
        (const uint8_t*)s_dvk->get_data(), s_dvk->get_size());
    ASSERT_EQ(err, ERR_OK);

#if defined (MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_cur_get(&used_after, &blocks_after);
    ASSERT_EQ(used_before, used_after);
    ASSERT_EQ(blocks_before, blocks_after);
#endif
}






