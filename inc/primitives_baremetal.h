#ifndef __PRIMITIVES_BAREMETAL_H__
#define __PRIMITIVES_BAREMETAL_H__

#ifndef BAREMETAL
#error "This file should only be included when BAREMETAL is defined"
#endif

#include <stdio.h>
#include <stddef.h>

#if __cplusplus
extern "C" {
#endif

#define PRIMITIVE_PANIC_DEFINED
void panic(const char* s, ...);
#define PANIC              panic

#define PRIMITIVE_SETBUF_DEFINED
static inline void crypto_setbuf(FILE* stream, char* buf)
{
    (void)stream;
    (void)buf;
}

#define PRIMITIVE_PRINTF_DEFINED
int crypto_printf(const char* format, ...);

#define PRIMITIVE_FPRINTF_DEFINED
int crypto_fprintf(FILE* stream, const char* format, ...);

int static_vsnprintf(char* buffer, size_t count, const char* format, __builtin_va_list va);

#define PRIMITIVE_VSNPRINTF_DEFINED
static inline int crypto_vsnprintf(char* str, size_t size, const char* format, __builtin_va_list ap)
{
    return static_vsnprintf(str, size, format, ap);
}

#if __cplusplus
};
#endif /* __cplusplus */

#endif /* !__PRIMITIVES_BAREMETAL_H__ */
