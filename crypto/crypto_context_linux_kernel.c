#include <crypto/crypto_context.h>

/**
 * This file is copied from crypto/crypto_context_linux_kernel.c
 * @note: do not modify if this file is in another directory
 */

#ifndef _LINUX_KERNEL_
#error "This file is only for Linux kernel"
#endif /* _LINUX_KERNEL_ */

#include <linux/bug.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/module.h>

void * stderr = NULL;

void
os_exit(int status)
{
    printk(KERN_NOTICE "driver exit: %d", status);
    BUG();
}

int os_snprintf(char* buf, size_t size, const char* format, ...)
{
    va_list args;
    int ret;
    va_start(args, format);
    ret = vsnprintf(buf, size, format, args);
    va_end(args);
    return ret;
}

int os_fprintf(void* stream, const char* format, ...)
{
    va_list args;
    int ret;
    va_start(args, format);
    ret = vprintk(format, args);
    va_end(args);
    return ret;
}

int
os_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
    return 0;
}

void print_backtrace(void)
{
    dump_stack();
}

void PANIC(const char* s, ...)
{
    va_list args;
    va_start(args, s);
    vprintk(s, args);
    va_end(args);
    print_backtrace();
    BUG();
}

int rand(void)
{
    return get_random_int();
}

