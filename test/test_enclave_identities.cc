#include <gtest/gtest.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <numeric>
#include <vector>
using namespace std;

#include "common.h"
#include <identities.h>
#include <enclave_common.h>

ident_remote_devices_t remote_devices = {
    .n_devices = 2,
    .devices = {
        [0] = {
            0x32,
            {
            "-----BEGIN PUBLIC KEY-----\n"
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEH6ZLw2s0NqHtnzP83vVdd6sInMk20M0I\n"
            "kZxSA91uBTwrP8FD505M/HDHaJ2tsxQySd+9x/4qlNQCiOpDUb3eTg==\n"
            "-----END PUBLIC KEY-----\0"},
            MAX_PUBKEY_PEM_SIZE,
        },
        [1] = {
            0x35,
            {
            "-----BEGIN PUBLIC KEY-----\n"
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEtraDYUMjm0hWpiiqjdjLVB/AJVUhXwMD\n"
            "jg87U76r2Efzn33bxHapCsXDZXNzrPkjpNmkBRcANAPhOTrG4UPq3w==\n"
            "-----END PUBLIC KEY-----\0"
            },
            MAX_PUBKEY_PEM_SIZE,
        },
    },
};

ident_nodes_t remote_nodes = {
    .n_nodes = 3,
    .nodes =
    {
        [0] = {.node_id = 0x5511, .device_id = 0x32, .slot = 0},
        [1] = {.node_id = 0x5514, .device_id = 0x32, .slot = 1},
        [2] = {.node_id = 0x5515, .device_id = 0x35, .slot = 2},
    },
};

static void load_slots()
{
    for (size_t i = 0; i < MAX_SLOTS; i++)
    {
        memset(remote_slots.slots[i], i, CRYPTO_HASH_SIZE);
    }
}

class EnclaveIdentities : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static bool init = false;
        if (init)
            return;
        crypto_init();
        enclave_platform_init();
        load_slots();
        init = true;
    }
    void TearDown() override
    {
    }
};

TEST_F(EnclaveIdentities, get_ident)
{
    char * pem;
    size_t pem_size;
    uint8_t * hash;

    err_t err;
    err = get_identity(0x5511, &pem, &pem_size, &hash);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(pem_size, remote_devices.devices[0].pem_size);
    EXPECT_EQ(memcmp(pem, remote_devices.devices[0].pem, pem_size), 0);
    EXPECT_EQ(memcmp(hash, remote_slots.slots[0], CRYPTO_HASH_SIZE), 0);

    err = get_identity(0x5514, &pem, &pem_size, &hash);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(pem_size, remote_devices.devices[0].pem_size);
    EXPECT_EQ(memcmp(pem, remote_devices.devices[0].pem, pem_size), 0);
    EXPECT_EQ(memcmp(hash, remote_slots.slots[1], CRYPTO_HASH_SIZE), 0);

    err = get_identity(0x5515, &pem, &pem_size, &hash);
    EXPECT_EQ(err, ERR_OK);
    EXPECT_EQ(pem_size, remote_devices.devices[1].pem_size);
    EXPECT_EQ(memcmp(pem, remote_devices.devices[1].pem, pem_size), 0);
    EXPECT_EQ(memcmp(hash, remote_slots.slots[2], CRYPTO_HASH_SIZE), 0);

    err = get_identity(0x5516, &pem, &pem_size, &hash);
    EXPECT_EQ(err, ERR_NOT_FOUND);
}
