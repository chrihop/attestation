#ifndef __BAREMETAL_STDLIB_H__
#define __BAREMETAL_STDLIB_H__

#include <string.h>

static inline int rand(void)
{
    static unsigned int seed = 0xdeadbeef;
    seed = seed * 1103515245 + 12345;
    return (unsigned int)(seed / 65536) % 32768;
}


#endif /* !__BAREMETAL_STDLIB_H__ */
