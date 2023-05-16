#include <primitives_baremetal.h>

#if __cplusplus
extern "C" {
#endif

void panic(const char* s, ...)
{
    (void)s;
    while (1)
    { (void)0; }
}

void * memcpy(void* dst, const void* src, unsigned int n)
{
    return __builtin_memcpy(dst, src, n);
}

void * memset(void* dst, int c, unsigned int n)
{
    return __builtin_memset(dst, c, n);
}

void * stderr = (void*)0;

static char output_buffer[256];

int crypto_printf(const char* format, ...)
{
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int ret = static_vsnprintf(output_buffer, sizeof(output_buffer), format, args);
    __builtin_va_end(args);
    return ret;
}

int crypto_fprintf(FILE* stream, const char* format, ...)
{
    (void)stream;
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int ret = static_vsnprintf(output_buffer, sizeof(output_buffer), format, args);
    __builtin_va_end(args);
    return ret;
}

#if __cplusplus
};
#endif
