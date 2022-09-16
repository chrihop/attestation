#ifndef _LIB_CRYPTO_MBEDTLS_IMPORT_HEADERS_H_
#define _LIB_CRYPTO_MBEDTLS_IMPORT_HEADERS_H_

/*******************************************************************************
 * mbedtls declarations (v3.2.1) - linked with libmbedcrypto.a
 ******************************************************************************/

#include "crypto_context.h"

#ifdef __cplusplus
extern "C"
{
#endif

#include <backend/mbedtls/include/mbedtls/ctr_drbg.h>
#include <backend/mbedtls/include/mbedtls/entropy.h>
#include <backend/mbedtls/include/mbedtls/sha256.h>
#include <backend/mbedtls/include/mbedtls/ecdsa.h>
#include <backend/mbedtls/include/mbedtls/ecdh.h>
#include <backend/mbedtls/include/mbedtls/chacha20.h>
#include <backend/mbedtls/include/mbedtls/chachapoly.h>
#include <backend/mbedtls/include/mbedtls/error.h>
#include <backend/mbedtls/include/mbedtls/memory_buffer_alloc.h>
#include <backend/mbedtls/include/mbedtls/base64.h>
#include <backend/mbedtls/include/mbedtls/pk.h>

#ifdef __cplusplus
};
#endif

#endif /* !_LIB_CRYPTO_MBEDTLS_IMPORT_HEADERS_H_ */
