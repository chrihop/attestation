#include <abstraction.h>

typedef struct enclave_node_t
{
    uint8_t hash[HASH_OUTPUT_SIZE];
} enclave_node_t;

typedef struct enclave_platform_context_t
{
    crypto_pki_context_t session;


} enclave_platform_context_t;
