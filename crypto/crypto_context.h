#ifndef _LIB_CRYPTO_CONTEXT_H_
#define _LIB_CRYPTO_CONTEXT_H_

int os_printf(const char* format, ...);


#ifdef _STD_LIBC_
/* link with standard libc files */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#define _bss __attribute__((section("__DATA, .bss")))
#else
#define _bss __attribute__((section(".bss")))
#endif

#define _inline inline __attribute__((always_inline))

#ifndef __cplusplus
typedef unsigned int bool;

#define FALSE (0)
#define TRUE  (1)
#endif

typedef int err_t;

#define ERR_OK           0
#define ERR_OUT_OF_BOUND 1001

void panic(const char* s, ...);

void memdump(const void* s, unsigned int n);

#elif defined(_LINUX_KERNEL_)

#define _bss __attribute__((section(".bss")))
#define _inline inline __attribute__((always_inline))

#define FALSE (0)
#define TRUE  (1)

typedef int err_t;

#define ERR_OK           0
#define ERR_OUT_OF_BOUND 1001

void panic(const char* s, ...);

void * memcpy(void *,const void *, unsigned long);

void * memset(void *,int, unsigned long);

int memcmp(const void *,const void *, unsigned long);

#elif (_CERTIKOS_KERNEL_)
/* link with certikos kernel */
#include <lib/common.h>
#include <lib/error.h>
#include <lib/string.h>

#define _bss             gcc_bss

typedef error_t err_t;

#define ERR_OK           0
#define ERR_OUT_OF_BOUND ERR_OUT_OF_BOUNDARY

#ifndef panic
#define panic(...) KERN_PANIC(__VA_ARGS__)
#endif

#else

#include <inc/baremetal/string.h>

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#define _bss        __attribute__((section(".bss")))

typedef int err_t;
#define ERR_OK           0
#define ERR_OUT_OF_BOUND 1


#ifndef panic
#define panic(...)                                                             \
    do                                                                         \
    {                                                                          \
        os_printf(__VA_ARGS__);                                                \
        os_exit(1);                                                            \
    } while (0)
#endif

#endif /* _STD_LIBC_ */

#endif /* _LIB_CRYPTO_CONTEXT_H_ */
