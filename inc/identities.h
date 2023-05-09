#ifndef _IDENTITIES_H_
#define _IDENTITIES_H_

/**
 * Each node is identified by their (device identity, hash) pair.
 *
 * Device identity is an EC public key (PEM format) that is distributed
 * by the integrator.
 *
 * Hash is the hash of the enclave binary after loaded into the memory.
 *
 * Each enclave node has MAX_SLOTS slots, to hold the hashes of other nodes.
 *
 * Slots are loaded by the secure loader.
 *
 * ```json
 * remote_devices = [
 * {
 *    uuid: 0x52,
 *    pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8..."
 * }, {...}, ...]
 *
 * nodes = [{
 *   uuid: 0x5576,
 *   slot: 3, ---> hash of the node
 *   device: 0x52,
 * }, {...}, ...]
 * ```
 */

#include <abstraction.h>
#include <config.h>

typedef long int uuid_t;

typedef struct ident_remote_device_t
{
    uuid_t device_id;
    char   pem[MAX_PUBKEY_PEM_SIZE];
    size_t pem_size;
} ident_remote_device_t;

typedef struct ident_remote_devices_t
{
    size_t                n_devices;
    ident_remote_device_t devices[MAX_REMOTE_DEVICES];
} ident_remote_devices_t;

typedef struct ident_node_t
{
    uuid_t  node_id;
    uuid_t  device_id;
    size_t  slot;
} ident_node_t;

typedef struct ident_nodes_t
{
    size_t       n_nodes;
    ident_node_t nodes[MAX_SLOTS];
} ident_nodes_t;

/**
 * Slots are mapped / loaded into a page by the secure loader.
 */
typedef struct ident_slots_t
{
    uint8_t slots[CRYPTO_HASH_SIZE][MAX_SLOTS];
    uint8_t end[] __attribute__((aligned(4096)));
} ident_slots_t __attribute__((aligned(4096)));

static_assert(sizeof(ident_slots_t) <= 4096, "ident_slots_t size too large");

#if defined(__cplusplus) && __cplusplus
extern "C"
{
#endif

extern __attribute((section(".rodata.trusted"))) ident_slots_t remote_slots;

ident_remote_device_t* find_device(uuid_t device_id);
ident_node_t* find_node(uuid_t node_id);
err_t get_identity(uuid_t node_id, char ** pem, size_t * pem_size, uint8_t ** hash);

#if defined(__cplusplus) && __cplusplus
}
#endif

#endif /* _IDENTITIES_H_ */
