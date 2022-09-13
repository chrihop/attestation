#include "crypto_context.h"

#ifdef _STD_LIBC_

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

void
memdump(const void* s, unsigned int n)
{
    uint8_t v;
    size_t  i, j;

    os_printf("-- %lu B --\n", n);
    os_printf("%08x: ", ((uintptr_t)s));
    for (i = 0; i < n; i++)
    {
        v = *(((uint8_t*)s) + i);
        os_printf("%02x", v);

        if ((i + 1) % 16 == 0 && i != 0)
        {
            os_printf(" | ");
            for (j = i - 15; j < i; j++)
            {
                v = *(((uint8_t*)s) + j);
                os_printf("%c", 0x20 <= v && v <= 0x7e ? v : '.');
            }
            os_printf(" |\n%08x: ", ((uintptr_t)s) + i + 1);
        }
        else if ((i + 1) % 8 == 0 && i != 0)
        {
            os_printf("    ");
        }
        else if ((i + 1) % 4 == 0 && i != 0)
        {
            os_printf("  ");
        }
        else
        {
            os_printf(" ");
        }
    }
    os_printf("\n------\n");
}

void
panic(const char* s, ...)
{
    va_list args;
    va_start(args, s);
    vprintf(s, args);
    va_end(args);
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
