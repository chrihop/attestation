cmake_minimum_required(VERSION 3.13)

# An external build script for creating enclave library to be linked with
# normal libc executables.
project(enclave-library)

set(CRYPTO_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(HOST_ARCH ${CMAKE_HOST_SYSTEM_PROCESSOR})

add_library(crypto
    STATIC
    crypto.c
    crypto_context.c
    root_key.c
    )

target_include_directories(crypto
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

add_dependencies(crypto
    mbedcrypto
    )

# enclave library is linked with linux kernel modules

add_library(crypto_linux
    STATIC
    crypto.c
    root_key.c
    )

target_compile_options(crypto_linux
    PRIVATE
    -nostdlib
)

target_include_directories(crypto_linux
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

target_compile_definitions(crypto_linux
    PRIVATE
    _LINUX_KERNEL_
    )
