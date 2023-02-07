#ifndef _THREADING_ALT_H_
#define _THREADING_ALT_H_

#if defined(POSIX_LIBC)
#include <threading_posix.h>
#elif defined(BAREMETAL)
#include <threading_baremetal.h>
#elif defined(CERTIKOS_USER)
#include <threading_certikos.h>
#elif defined(LINUX_KERNEL)
#include <threading_linux.h>
#endif

#ifndef THREADING_MUTEX_TYPE_DEFINED
#error "mutex_t is not defined for this platform"
#endif

#ifndef THREADING_MUTEX_INIT_DEFINED
#error "crypto_mutex_init() is not defined for this platform"
#endif

#ifndef THREADING_MUTEX_FREE_DEFINED
#error "crypto_mutex_free() is not defined for this platform"
#endif

#ifndef THREADING_MUTEX_LOCK_DEFINED
#error "crypto_mutex_lock() is not defined for this platform"
#endif

#ifndef THREADING_MUTEX_UNLOCK_DEFINED
#error "crypto_mutex_unlock() is not defined for this platform"
#endif

#endif /* _THREADING_ALT_H_ */
