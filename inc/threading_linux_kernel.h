#ifndef _THREADING_LINUX_KERNEL_H_
#define _THREADING_LINUX_KERNEL_H_

#ifndef _LINUX_KERNEL_
#error "This file should only be included in Linux kernel code"
#endif

#include <linux/types.h>
#include <linux/mutex.h>

#if defined(__cplusplus) && __cplusplus
extern "C" {
#endif

typedef struct mutex mbedtls_threading_mutex_t;
#define THREADING_MUTEX_TYPE_DEFINED

static inline void crypto_mutex_init(mbedtls_threading_mutex_t* m)
{
    mutex_init(m);
}
#define THREADING_MUTEX_INIT_DEFINED

static inline void crypto_mutex_free(mbedtls_threading_mutex_t* m)
{
    mutex_destroy(m);
}
#define THREADING_MUTEX_FREE_DEFINED

static inline int crypto_mutex_lock(mbedtls_threading_mutex_t* m)
{
    mutex_lock(m);
    return 0;
}
#define THREADING_MUTEX_LOCK_DEFINED

static inline int crypto_mutex_unlock(mbedtls_threading_mutex_t* m)
{
    mutex_unlock(m);
    return 0;
}
#define THREADING_MUTEX_UNLOCK_DEFINED

#if defined(__cplusplus) && __cplusplus
};
#endif


#endif /* _THREADING_LINUX_KERNEL_H_ */
