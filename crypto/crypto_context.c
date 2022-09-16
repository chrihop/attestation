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

#else

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

#endif /* _STD_LIBC_ */
