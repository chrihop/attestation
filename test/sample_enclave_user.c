#include <abstraction.h>
#include <enclave_common.h>
#include <identities.h>

int main(int argc, char ** argv)
{
    crypto_init();

    unsigned char key[32];
    crypto_rng(key, 32);
    for (int i = 0; i < 32; i++)
    {
        crypto_printf("%02x", key[i]);
    }
    crypto_printf("\n");

    char * pem;
    size_t pem_size;
    uint8_t * hash;
    err_t rv;
    rv = get_identity(0x5533, &pem, &pem_size, &hash);
    crypto_printf("get_identity: %s\n", rv == ERR_OK? "OK" : "FAIL");
    return 0;
}

__attribute__((section(".text.main")))
__attribute__((noreturn))
__attribute__((weak))
void _start()
{
    main(0, 0);
    while (1) {}
}

