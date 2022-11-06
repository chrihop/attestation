#include "crypto_context.h"

#ifdef _STD_LIBC_

#include <execinfo.h>
void
os_exit(int status)
{
    exit(status);
}

int
os_snprintf(char* s, size_t n, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(s, n, format, args);
    va_end(args);
    return 0;
}

int
os_fprintf(FILE* stream, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stream, format, args);
    va_end(args);
    return 0;
}

int
os_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    return 0;
}

void print_backtrace(void)
{
#ifdef _STD_LIBC_
    void* callstack[32];
    int i, frames = backtrace(callstack, 32);
    char** strs = backtrace_symbols(callstack, frames);
    for (i = 0; i < frames; ++i)
    {
        if (i == 3)
        {
            printf(" ===> ");
        }
        else
        {
            printf("      ");
        }
        printf("%s\n", strs[i]);
    }
    free(strs);
#endif
}

void
panic(const char* s, ...)
{
    va_list args;
    va_start(args, s);
    vprintf(s, args);
    va_end(args);
    print_backtrace();
    exit(0);
}

#elif defined(_CERTIKOS_KERNEL_)

void
os_exit(int status)
{
    KERN_PANIC("kernel halt (%d)\n", status);
}

int
os_snprintf(char* s, size_t n, const char* format, ...)
{
    int     rv;
    va_list args;

    va_start(args, format);
    rv = vsprintf(sprint_puts, s, format, &args);
    va_end(args);
    return (rv);
}

unsigned char  _stderr[1];
unsigned char* stderr = _stderr;

int
os_fprintf(void* stream, const char* format, ...)
{
    int     rv;
    va_list args;

    dprintf("0x%lx |> ", stream);
    va_start(args, format);
    rv = vdprintf(cputs, format, &args);
    va_end(args);
    return (rv);
}

int
os_printf(const char* format, ...)
{
    int     rv;
    va_list args;

    va_start(args, format);
    rv = vdprintf(cputs, format, &args);
    va_end(args);
    return (rv);
}

#else

#include <stddef.h>

typedef __builtin_va_list va_list;

#define va_start(v,l)	__builtin_va_start(v,l)
#define va_end(v)	__builtin_va_end(v)
#define va_arg(v,l)	__builtin_va_arg(v,l)

extern int __crypto_import_vprintf(const char* format, va_list * ap);
extern int __crypto_import_panic(int status);


int
os_snprintf(char* s, size_t n, const char* format, ...)
{
    int     rv;
    va_list args;

    va_start(args, format);
    rv = __builtin_vsprintf(s, format, args);
    va_end(args);
    return (rv);
}

__attribute__((weak)) unsigned char  _stderr[1], _stdout[1];
__attribute__((weak)) unsigned char* stderr = _stderr;
__attribute__((weak)) unsigned char* stdout = _stdout;

int
os_printf(const char* format, ...)
{
    int     rv;
    va_list args;

    va_start(args, format);
    rv = __crypto_import_vprintf(format, &args);
    va_end(args);
    return (rv);
}

int
os_fprintf(void* stream, const char* format, ...)
{
    int     rv;
    va_list args;

    if (stream == stderr) {os_printf("ERR |> ");}
    else if (stream != stdout) {os_printf("0x%lx |> ", stream);}

    va_start(args, format);
    rv = __crypto_import_vprintf(format, &args);
    va_end(args);
    return (rv);
}

void
os_exit(int status)
{
    int rv;
    va_list args;

    os_printf("panic exit (%d)", status);
    __crypto_import_panic(status);
}

#endif /* _STD_LIBC_ */
