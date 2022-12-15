#ifndef _LINUX_KERNEL_LIMITS_H_
#define _LINUX_KERNEL_LIMITS_H_

#include <linux/types.h>

#ifdef INT_MAX
#undef INT_MAX
#define INT_MAX     __INT_MAX__
#endif

#ifdef SIZE_MAX
#undef SIZE_MAX
#define SIZE_MAX    __SIZE_MAX__
#endif

#endif /* !_LINUX_KERNEL_LIMITS_H_ */
