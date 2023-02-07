#ifndef _PRIMITIVES_POSIX_H_
#define _PRIMITIVES_POSIX_H_

#ifndef POSIX_LIBC
#error "This file should only be included when POSIX_LIBC is defined"
#endif

#include <stdio.h>

#if __cplusplus
extern "C" {
#endif

#define PRIMITIVE_PANIC_DEFINED
void PANIC(const char* s, ...);

#define PRIMITIVE_SETBUF_DEFINED
#define crypto_setbuf       setbuf

#define PRIMITIVE_PRINTF_DEFINED
#define crypto_printf       printf

#define PRIMITIVE_FPRINTF_DEFINED
#define crypto_fprintf      fprintf

#define PRIMITIVE_VSNPRINTF_DEFINED
#define crypto_vsnprintf    vsnprintf

#if __cplusplus
};
#endif


#endif /* _PRIMITIVES_POSIX_H_ */
