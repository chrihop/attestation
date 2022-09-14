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
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_compile_definitions(crypto
    PRIVATE
    _STD_LIBC_)
