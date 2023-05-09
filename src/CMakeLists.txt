cmake_minimum_required(VERSION 3.13)

include_directories(
    ${ATTESTATION_BACKEND_DIR}/${BACKEND}/include
    ${ATTESTATION_TOP_DIR}/inc
)

set (ATTESTATION_SOURCE
    root_key.c
    ${BACKEND}_abstraction.c
    primitives_${BUILD_FOR}.c
    ${EXTRA_C_SRC}
    )

add_library(crypto_abstract
    STATIC
    ${ATTESTATION_SOURCE}
    )

add_dependencies(crypto_abstract
    backend
    )

if (BACKEND STREQUAL "mbedtls")
    target_link_libraries(crypto_abstract
        mbedcrypto
    )
endif()

add_library(enclave_common
    STATIC
    identities.c
    enclave_common.c
    enclave_protocol_dds.c
    )

target_link_libraries(enclave_common
    PRIVATE
    crypto_abstract
    )

add_dependencies(enclave_common
    crypto_abstract
    )

add_executable(dummy_main
    dummy_main.c
    )

target_link_libraries(dummy_main
    PRIVATE
    crypto_abstract
    mbedcrypto
    enclave_common
    )
