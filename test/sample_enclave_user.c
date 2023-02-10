#include <abstraction.h>

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

