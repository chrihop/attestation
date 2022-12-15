#include <enclave.h>
#include "crypto/crypto_context.h"
#include "crypto/crypto.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct enclave_key_store_t root_key;

struct enclave
{
    crypto_hash_context_t           hash;
    struct crypto_dh_context_t      ctx;
    struct crypto_ds_signature_t    signature;
    struct crypto_dh_key_t          key;
    struct crypto_sc_mac_context_t  stream;
};

struct client
{
    struct enclave_session_mgmt_t   mgmt;
    struct crypto_ds_public_key_t   trusted;
    struct crypto_dh_key_t          key;
    struct crypto_sc_mac_context_t  stream;
};

struct channel
{
    struct crypto_dh_curve_t            curve;
    struct enclave_attestation_report_t report;
    size_t                              len;
    uint8_t                             open[128 + 16];
};

struct install
{
    uint8_t                             hash[32]; /* the hash of the binary */
    struct crypto_ds_public_key_t       device_pubkey; /* device public key */
};

static struct install inst;
static struct channel ch;
static struct enclave e;

uint8_t binary[128] = {"my code and data ..."};

void install(void)
{
    crypto_hash_init(&e.hash);
    crypto_hash_append(&e.hash, binary, 128);
    crypto_hash_report(&e.hash, inst.hash);
    crypto_ds_export_public_key(&root_key.device_key, &inst.device_pubkey);
}

void enclave_launch(void)
{
    /* measure */
    crypto_hash_init(&e.hash);
    crypto_hash_append(&e.hash, binary, 128);
    uint8_t sha[32];
    crypto_hash_report(&e.hash, sha);

    /* sign by device */
    crypto_sign_hashed(&root_key.session.client, sha, &e.signature);
}

void enclave_attestation(void)
{
    enclave_ra_response(&e.ctx, &root_key, &ch.curve, &e.signature, &ch.report, &e.key);
    crypto_sc_mac_init(&e.stream, e.key.key, e.key.len, FALSE);
}

static struct client c;

void client_handshake(void)
{
    struct enclave_attestation_challenge_t challenge = {.in_use = FALSE};
    enclave_ra_challenge(&challenge);
    memcpy(&ch.curve, &challenge.curve, sizeof(struct crypto_dh_curve_t));
    printf("challenge token: ");
    for (int i = 0; i < ch.curve.len; i++) {
        printf("%02x ", ch.curve.curve[i]);
    }
    printf("\n");

    /* do remote attestation */
    enclave_attestation();

    printf("report token: ");
    for (int i = 0; i < sizeof(struct enclave_attestation_report_t); i++) {
        printf("%02x ", ((uint8_t *) &ch.report)[i]);
    }
    printf("\n");

    /* verify */
    bool match = enclave_ra_verify(&challenge, &c.mgmt, &inst.device_pubkey, inst.hash,
        &ch.report, &c.key);
    if (!match)
    {
        PANIC("error: attestation failed!\n");
    }

    printf("peer identity verified!\n");

    crypto_sc_mac_init(&c.stream, c.key.key, c.key.len, TRUE);
}

void send(uint8_t * msg, size_t len)
{
    crypto_sc_mac_encrypt(&c.stream, msg, len, ch.open, &ch.len);
}

#define min(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

static uint8_t buffer[128];

void recv()
{
    printf("read open channel for %lu bytes: ", ch.len);
    for (int i = 0; i < min(128 + 32, ch.len); i++)
    {
        printf("%02x ", ch.open[i]);
    }
    printf("\n");
    size_t len;
    crypto_sc_mac_decrypt(&e.stream, ch.open, ch.len, buffer, &len);
    printf("decrypt: %s\n", buffer);
}

int main(int argc, char ** argv)
{
    crypto_init();
    enclave_key_native(&root_key);
    printf("install device / enclave identities ...\n");
    install();

    printf("system booting ...\n");
    enclave_session_mgmt_init(&c.mgmt);

    printf("load enclave ...\n");
    enclave_launch();

    printf("start handshake ...\n");
    client_handshake();

    printf("start message transfer ...\n");
    uint8_t * msg = "Hello, world!";
    send(msg, strlen(msg));
    recv();
}
