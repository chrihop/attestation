#ifndef _CRYPTO_CONTEXT_LINUX_H_
#define _CRYPTO_CONTEXT_LINUX_H_

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/limits.h>

typedef int FILE;

extern int * stderr;

extern int rand(void);

#endif /* !_CRYPTO_CONTEXT_LINUX_H_ */
