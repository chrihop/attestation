#ifndef __THREADING_BAREMETAL_H__
#define __THREADING_BAREMETAL_H__

#ifndef BAREMETAL
#error "This file is for baremetal only"
#endif

struct ticket_lock_t {
    volatile unsigned int next_ticket;
    volatile unsigned int now_serving;
};

typedef struct ticket_lock_t ticket_lock_t;

static inline void ticket_lock_init(ticket_lock_t *lock)
{
    lock->next_ticket = 0;
    lock->now_serving = 0;
}

static inline int ticket_lock_acquire(ticket_lock_t *lock)
{
    unsigned int my_ticket = __sync_fetch_and_add(&lock->next_ticket, 1);
    while (lock->now_serving != my_ticket) {
        (void)0;
    }
    return 1;
}

static inline int ticket_lock_release(ticket_lock_t *lock)
{
    __sync_fetch_and_add(&lock->now_serving, 1);
    return 1;
}

static inline void ticket_lock_free(ticket_lock_t *lock)
{
    (void)lock;
}

typedef ticket_lock_t mbedtls_threading_mutex_t;
#define THREADING_MUTEX_TYPE_DEFINED

static inline void crypto_mutex_init(mbedtls_threading_mutex_t* m)
{
    ticket_lock_init(m);
}
#define THREADING_MUTEX_INIT_DEFINED

static inline void crypto_mutex_free(mbedtls_threading_mutex_t* m)
{
    ticket_lock_free(m);
}
#define THREADING_MUTEX_FREE_DEFINED

static inline int crypto_mutex_lock(mbedtls_threading_mutex_t* m)
{
    return ticket_lock_acquire(m);
}
#define THREADING_MUTEX_LOCK_DEFINED

static inline int crypto_mutex_unlock(mbedtls_threading_mutex_t* m)
{
    return ticket_lock_release(m);
}
#define THREADING_MUTEX_UNLOCK_DEFINED

#endif /* !__THREADING_BAREMETAL_H__ */
