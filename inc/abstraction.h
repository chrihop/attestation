#ifndef _ATTESTATION_ABSTRACTION_H_
#define _ATTESTATION_ABSTRACTION_H_

#if defined(BACKEND_MBEDTLS)
#include <mbedtls_abstraction.h>
#endif

#if __cplusplus
extern "C" {
#endif

void crypto_init(void);

#if __cplusplus
};
#endif



#endif /* _ATTESTATION_ABSTRACTION_H_ */
