#ifndef _BAREMETAL_LIMITS_H_
#define _BAREMETAL_LIMITS_H_

#define CHAR_BIT 8

#define INT_MAX __INT_MAX__

#define INT_MIN (-INT_MAX - 1)

#define UINT_MAX (INT_MAX * 2U + 1U)

#endif /* !_BAREMETAL_LIMITS_H_ */
