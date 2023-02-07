#ifndef __BAREMETAL_STDIO_H__
#define __BAREMETAL_STDIO_H__

typedef struct {
    int fd;
} FILE;

extern void * stderr;

#endif /* !__BAREMETAL_STDIO_H__ */
