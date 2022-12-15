set (MBEDTLS_BUILD_DIR      build-${CMAKE_SYSTEM_PROCESSOR})

find_package(Python REQUIRED)
set (CMAKE_PYTHON ${Python_EXECUTABLE})

find_package(Git)

find_program(SED_EXECUTABLE sed
    REQUIRED)

set (MBEDTLS_SRC_DIR    ${ATTESTATION_TOP_DIR}/backend/mbedtls)
set (MBEDTLS_AS_SUBPROJECT true)
set (MbedTLS_DIR ${ATTESTATION_TOP_DIR}/backend/mbedtls/cmake)
list (APPEND CMAKE_MODULE_PATH
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/cmake
)
set (CMAKE_CROSSCOMPILING ON)
set (CMAKE_TOOLCHAIN_FILE ${ATTESTATION_TOP_DIR}/config/${CMAKE_SYSTEM_PROCESSOR}.cmake)
set (ENABLE_TESTING OFF)

# Resolve conflicts with google benchmark

find_program(SED
    sed
    REQUIRED)

file(COPY_FILE
    ${MBEDTLS_SRC_DIR}/programs/test/benchmark.c
    ${MBEDTLS_SRC_DIR}/programs/test/mbedtls-benchmark.c
    ONLY_IF_DIFFERENT)

execute_process(
    COMMAND ${SED} -i -E "s/^(\\s*)benchmark\$/\\1mbedtls-benchmark/g"  ${MBEDTLS_SRC_DIR}/programs/test/CMakeLists.txt
    COMMAND_ECHO STDOUT
)
# --

file(COPY_FILE
    ${ATTESTATION_TOP_DIR}/config/mbedtls_os.h
    ${MBEDTLS_SRC_DIR}/include/mbedtls/os.h
    ONLY_IF_DIFFERENT)

add_subdirectory(mbedtls)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/mbedtls_config.tstamp
    COMMAND ${GIT_EXECUTABLE} checkout -- include/mbedtls/mbedtls_config.h
    COMMAND ${CMAKE_PYTHON} scripts/config.py --write include/mbedtls/mbedtls_config.h crypto_baremetal
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_HAVE_ASM
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_NO_UDBL_DIVISION
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_MEMORY
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_MEMORY_ALIGN_MULTIPLE 8
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_MEMORY_DEBUG
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_CIPHER_MODE_CBC
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_CIPHER_PADDING_PKCS7
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECP_DP_SECP192R1_ENABLED
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECP_DP_SECP256R1_ENABLED
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECP_DP_CURVE25519_ENABLED
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECP_NIST_OPTIM
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_VERSION_FEATURES
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_AES_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_AESNI_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_CHACHA20_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_CIPHER_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_CTR_DRBG_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ENTROPY_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_NO_PLATFORM_ENTROPY
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_TEST_NULL_ENTROPY
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECDH_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECDSA_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_ECDSA_DETERMINISTIC
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ECP_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ERROR_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_OID_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_MD_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_SHA256_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_SHA512_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ASN1_PARSE_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_ASN1_WRITE_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_BASE64_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_BIGNUM_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PEM_WRITE_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PK_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PK_PARSE_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PK_WRITE_C
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_EXIT_MACRO os_exit
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_FPRINTF_MACRO os_fprintf
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_PRINTF_MACRO os_printf
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h set MBEDTLS_PLATFORM_SNPRINTF_MACRO os_snprintf
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_CIPHER_NULL_CIPHER
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PSA_CRYPTO_CLIENT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PSA_CRYPTO_DRIVERS
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_SHA256_SMALLER
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_SHA512_SMALLER
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PLATFORM_SETBUF_ALT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PLATFORM_EXIT_ALT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PLATFORM_PRINTF_ALT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PLATFORM_SNPRINTF_ALT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_PLATFORM_VSNPRINTF_ALT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
    COMMAND ${CMAKE_PYTHON} scripts/config.py --file  include/mbedtls/mbedtls_config.h unset MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
    COMMAND ${CMAKE_COMMAND} -E echo "#include \"os.h\"" > include/mbedtls/mbedtls_config_os.h
    COMMAND ${CMAKE_COMMAND} -E cat include/mbedtls/mbedtls_config.h >> include/mbedtls/mbedtls_config_os.h
    COMMAND ${CMAKE_COMMAND} -E rename include/mbedtls/mbedtls_config_os.h include/mbedtls/mbedtls_config.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/mbedtls_config.tstamp
    WORKING_DIRECTORY ${MBEDTLS_SRC_DIR}
    COMMENT "configure mbedtls ..."
    VERBATIM
    USES_TERMINAL
)

add_custom_target(mbedtls-config
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/mbedtls_config.tstamp)

add_dependencies(mbedcrypto mbedtls-config)

add_custom_command(
    OUTPUT mbedtls.patch.tstamp
#    COMMAND ${GIT_EXECUTABLE} apply --reverse --check ${ATTESTATION_TOP_DIR}/config/mbedtls_v3.2.1.patch || ${GIT_EXECUTABLE} apply ${ATTESTATION_TOP_DIR}/config/mbedtls_v3.2.1.patch
    COMMAND ${CMAKE_COMMAND} -E touch mbedtls.patch.tstamp
    WORKING_DIRECTORY ${MBEDTLS_SRC_DIR}
    COMMENT "patch mbedtls for linux kernel module ..."
    VERBATIM
)

add_custom_target(mbedtls-patch
    DEPENDS mbedtls.patch.tstamp)
