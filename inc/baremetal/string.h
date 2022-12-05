#ifndef __BAREMETAL_STRING_H__
#define __BAREMETAL_STRING_H__

#include <stddef.h>

static inline void *memcpy (void *__restrict __dest,
    const void *__restrict __src, unsigned long __n)
{
    return __builtin_memcpy(__dest, __src, __n);
}

static inline void * memmove (void *__dest, const void *__src, unsigned long __n)
{
    return __builtin_memmove(__dest, __src, __n);
}

static inline int memcmp (const void *__s1, const void *__s2, unsigned long __n)
{
    return __builtin_memcmp(__s1, __s2, __n);
}

static inline void *memset (void *__s, int __c, unsigned long __n)
{
    return __builtin_memset(__s, __c, __n);
}

static inline int strcmp (const char *__s1, const char *__s2)
{
    return __builtin_strcmp(__s1, __s2);
}

static inline long unsigned int strlen (const char *__s)
{
    return __builtin_strlen(__s);
}

static inline char * strstr (const char *__s1, const char *__s2)
{
    return __builtin_strstr(__s1, __s2);
}

#endif /* !__BAREMETAL_STRING_H__ */
