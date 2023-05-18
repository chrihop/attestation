#ifndef __THREADING_CERTIKOS_USER_H__
#define __THREADING_CERTIKOS_USER_H__

/**
 * @note CertiKOS user does not support multithreading,
 * mutex is unnecessary.
 */

#ifndef CERTIKOS_USER
#error "This file is for CertiKOS user only"
#endif

typedef int mbedtls_threading_mutex_t;
#define THREADING_MUTEX_TYPE_DEFINED

static inline void crypto_mutex_init(mbedtls_threading_mutex_t* m)
{
    (void)m;
}
#define THREADING_MUTEX_INIT_DEFINED

static inline void crypto_mutex_free(mbedtls_threading_mutex_t* m)
{
    (void)m;
}
#define THREADING_MUTEX_FREE_DEFINED

static inline int crypto_mutex_lock(mbedtls_threading_mutex_t* m)
{
    (void)m;
    return 0;
}
#define THREADING_MUTEX_LOCK_DEFINED

static inline int crypto_mutex_unlock(mbedtls_threading_mutex_t* m)
{
    (void)m;
    return 0;
}
#define THREADING_MUTEX_UNLOCK_DEFINED

#endif /* __THREADING_CERTIKOS_USER_H__ */
