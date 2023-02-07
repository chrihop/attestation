#include <primitives_posix.h>

#include <malloc.h>
#include <execinfo.h>
#include <stdarg.h>
#include <stdlib.h>

#if __cplusplus
extern "C" {
#endif

void print_backtrace(void)
{
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
}

void PANIC(const char* s, ...)
{
    va_list args;
    va_start(args, s);
    vprintf(s, args);
    va_end(args);
    print_backtrace();
    exit(1);
}

#if __cplusplus
};
#endif
