#ifndef _MBEDTLS_OS_H_
#define _MBEDTLS_OS_H_

#ifndef _STD_LIBC_
extern void * stderr;
#else
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
void os_exit(int status);

int os_snprintf(char * s, unsigned long n, const char * format, ...);

int os_fprintf(void *stream, const char *format, ...);

int os_printf(const char * format, ...);

#ifdef __cplusplus
};
#endif


#endif /* !_MBEDTLS_OS_H_ */

