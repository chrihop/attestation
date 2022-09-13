#ifndef _LIB_CRYPTO_CONTEXT_H_
#define _LIB_CRYPTO_CONTEXT_H_

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

typedef unsigned int bool;

#define FALSE (0)
#define TRUE  (1)

typedef int err_t;

#define ERR_OK           0
#define ERR_OUT_OF_BOUND 1001

typedef unsigned int bool;

#define FALSE (0)
#define TRUE  (1)

void panic(const char* s, ...);

void memdump(const void* s, unsigned int n);

#else /* _STD_LIBC_ */
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

#endif /* _STD_LIBC_ */

int os_printf(const char* format, ...);

#endif /* _LIB_CRYPTO_CONTEXT_H_ */
