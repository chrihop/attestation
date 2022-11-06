#ifndef __BAREMETAL_STDDEF_H__
#define __BAREMETAL_STDDEF_H__

#ifndef __SIZE_TYPE__
#define __SIZE_TYPE__ long unsigned int
#endif
#if !(defined (size_t))
typedef __SIZE_TYPE__ size_t;
#endif

#if !(defined uintptr_t)
typedef unsigned long int	uintptr_t;
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#endif /* !__BAREMETAL_STDDEF_H__ */
