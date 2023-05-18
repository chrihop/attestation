#ifndef __PRIMITIVES_CERTIKOS_USER_H__
#define __PRIMITIVES_CERTIKOS_USER_H__

#ifndef CERTIKOS_USER
#error "This file is for CertiKOS user only"
#endif

#include <debug.h>
#include <stdio.h>
#include <stdarg.h>

#define PRIMITIVE_PANIC_DEFINED /* defined in <debug.h> */

#define PRIMITIVE_SETBUF_DEFINED
static inline void crypto_setbuf(FILE* stream, char* buf)
{
    (void)stream;
    (void)buf;
}

#define PRIMITIVE_PRINTF_DEFINED
#define crypto_printf       printf

#define PRIMITIVE_FPRINTF_DEFINED
static inline int crypto_fprintf(FILE* stream, const char* format, ...)
{
    int rv;
    va_list ap;
    va_start(ap, format);
    rv = vfprintf(stream, format, &ap);
    va_end(ap);
    return rv;
}

#define PRIMITIVE_VSNPRINTF_DEFINED
static inline int crypto_vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return vsnprintf(str, size, format, &ap);
}

#endif /* __PRIMITIVES_CERTIKOS_USER_H__ */
