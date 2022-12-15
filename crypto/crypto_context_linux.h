#ifndef _CRYPTO_CONTEXT_LINUX_H_
#define _CRYPTO_CONTEXT_LINUX_H_

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/limits.h>

typedef int FILE;

//extern int * stderr;

extern int rand(void);

static const char
__UNIQUE_ID(license)[] __attribute__((__used__))
__attribute__((__section__(".modinfo"))) __attribute__((__aligned__(1)))
= KBUILD_MODNAME "."
                 "license"
                 "="
                 "Dual BSD/GPL";

#endif /* !_CRYPTO_CONTEXT_LINUX_H_ */
