#ifndef _THREADING_POSIX_H_
#define _THREADING_POSIX_H_

#ifndef POSIX_LIBC
#error "This file should only be included when POSIX_LIBC is defined"
#endif

#include <pthread.h>
#include <stdio.h>

#if __cplusplus
extern "C" {
#endif

typedef pthread_mutex_t mbedtls_threading_mutex_t;
#define THREADING_MUTEX_TYPE_DEFINED

static inline void crypto_mutex_init(mbedtls_threading_mutex_t* m)
{
    pthread_mutex_init(m, NULL);
}
#define THREADING_MUTEX_INIT_DEFINED

static inline void crypto_mutex_free(mbedtls_threading_mutex_t* m)
{
    pthread_mutex_destroy(m);
}
#define THREADING_MUTEX_FREE_DEFINED

static inline int crypto_mutex_lock(mbedtls_threading_mutex_t* m)
{
    return pthread_mutex_lock(m);
}
#define THREADING_MUTEX_LOCK_DEFINED

static inline int crypto_mutex_unlock(mbedtls_threading_mutex_t* m)
{
    return pthread_mutex_unlock(m);
}
#define THREADING_MUTEX_UNLOCK_DEFINED

#if __cplusplus
};
#endif


#endif /* _THREADING_POSIX_H_ */
