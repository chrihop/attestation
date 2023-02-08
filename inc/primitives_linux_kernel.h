#ifndef _PRIMITIVES_LINUX_KERNEL_H_
#define _PRIMITIVES_LINUX_KERNEL_H_

#ifndef _LINUX_KERNEL_
#error "This file should only be included in Linux kernel code"
#endif

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

typedef long unsigned int size_t;

#include <linux/types.h>
//#include <linux/kernel.h>
#include <linux/string.h>
//#include <linux/limits.h>

typedef int FILE;

int rand(void);

#endif /* _PRIMITIVES_LINUX_KERNEL_H_ */
