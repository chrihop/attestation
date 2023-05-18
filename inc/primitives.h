#ifndef _PRIMITIVES_H_
#define _PRIMITIVES_H_

#if defined(POSIX_LIBC)
#include <primitives_posix.h>
#elif defined(BAREMETAL)
#include <primitives_baremetal.h>
#elif defined(CERTIKOS_USER)
#include <primitives_certikos_user.h>
#elif defined(CERTIKOS_KERNEL)
#include <primitives_certikos_kernel.h>
#elif defined(LINUX_KERNEL)
#include <primitives_linux.h>
#endif

#ifndef PRIMITIVE_PANIC_DEFINED
#error "panic() is not defined for this platform"
#endif

static inline void crypto_exit(int status)
{
    PANIC("crypto_exit() with status %d\n", status);
}

#ifndef PRIMITIVE_SETBUF_DEFINED
#error "setbuf() is not defined for this platform"
#endif

#ifndef PRIMITIVE_PRINTF_DEFINED
#error "printf() is not defined for this platform"
#endif

#ifndef PRIMITIVE_FPRINTF_DEFINED
#error "fprintf() is not defined for this platform"
#endif

#ifndef PRIMITIVE_VSNPRINTF_DEFINED
#error "vsnprintf() is not defined for this platform"
#endif

static inline int crypto_snprintf(char *str, size_t size, const char *format, ...)
{
    __builtin_va_list ap;
    int ret;

    __builtin_va_start(ap, format);
    ret = crypto_vsnprintf(str, size, format, ap);
    __builtin_va_end(ap);

    return ret;
}

#if __cplusplus
#define static_assert static_assert
#else
#define static_assert _Static_assert
#endif

enum err_t
{
    ERR_OK = 0,
    ERR_INVALID_PARAM,
    ERR_INVALID_SIZE,
    ERR_INVALID_ID,
    ERR_INVALID_PROTOCOL,
    ERR_VERIFICATION_FAILED,
    ERR_BAD_STATE,
    ERR_NOT_IMPLEMENTED,
    ERR_OUT_OF_MEMORY,
    ERR_NOT_FOUND,
    ERR_UNKNOWN,

    MAX_ERRORS
};

typedef enum err_t err_t;

#define _out_
#define _in_
#define _in_out_

enum key_type_t
{
    KT_SYMMETRIC = 0,
    KT_ASYMMETRIC,

    MAX_KEY_TYPES
};

typedef enum key_type_t key_type_t;

enum secure_hash_status_t
{
    SHS_NOT_STARTED = 0,
    SHS_IN_PROGRESS,
    SHS_DONE,

    MAX_SECURE_HASH_STATUS
};

typedef enum secure_hash_status_t secure_hash_status_t;

#ifndef __STR
#define __STR(x) #x
#endif

#ifndef STR
#define STR(x) __STR(x)
#endif

#if DEBUG_BUILD
#define crypto_assert(x) \
    do { \
        if (!(x)) \
        { \
            PANIC("[P] " __FILE__ ":" STR(__LINE__) " in %s():" \
            " assertion failed: %s\n", __FUNCTION__, #x); \
        } \
    } while (0)
#else
#define crypto_assert(x) do {} while (0)
#endif



#endif /* _PRIMITIVES_H_ */
