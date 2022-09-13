#ifndef _MBEDTLS_OS_H_
#define _MBEDTLS_OS_H_

void os_exit(int status);

int os_snprintf(char * s, unsigned long n, const char * format, ...);

int os_fprintf(void *stream, const char *format, ...);

int os_printf(const char * format, ...);

#endif /* !_MBEDTLS_OS_H_ */

