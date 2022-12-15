cmake_minimum_required(VERSION 3.13)

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE HOST_ARCH
    )

string(STRIP ${HOST_ARCH} HOST_ARCH)

#if (NOT CMAKE_TOOLCHAIN_FILE)
#    set(CMAKE_TOOLCHAIN_FILE  ${CMAKE_SOURCE_DIR}/target-linux-${HOST_ARCH}-gnu.cmake)
#endif()
#
#message("toolchain: " ${CMAKE_TOOLCHAIN_FILE})

project(attestation)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(ATTESTATION_TOP_DIR         ${CMAKE_CURRENT_SOURCE_DIR})
set(ATTESTATION_TOP_BUILD_DIR   ${CMAKE_CURRENT_BINARY_DIR})

set(CRYPTO_DIR                  ${ATTESTATION_TOP_DIR}/crypto)
set(CRYPTO_BUILD_DIR            ${ATTESTATION_TOP_BUILD_DIR}/crypto)

set(BACKEND_DIR                 ${ATTESTATION_TOP_DIR}/backend)
set(BACKEND_BUILD_DIR           ${ATTESTATION_TOP_BUILD_DIR}/backend)

option(BAREMETAL "Baremetal build" OFF)
option(CERTIKOS_USER "CertikOS user build" OFF)

if (BAREMETAL)

    if (CERTIKOS_USER)

        add_definitions(-D_CERTIKOS_USER_)

    else()
        message(STATUS "Baremetal build")

        add_compile_options(-nostdlib -nostdinc -ffreestanding -fno-builtin
            -fno-common -fno-exceptions -fno-stack-protector
            -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing
            -fno-omit-frame-pointer -fno-strict-overflow -fno-delete-null-pointer-checks
            -fno-PIE -fno-pic -fno-pie -fno-pic -fno-stack-protector -fno-unwind-tables
            -fno-asynchronous-unwind-tables -fno-exceptions -fno-omit-frame-pointer
            -fno-delete-null-pointer-checks)

        add_link_options(
            -nostdlib -nostdinc -ffreestanding -fno-builtin
            -fno-common -fno-exceptions -fno-stack-protector
            -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing
            -fno-omit-frame-pointer -fno-strict-overflow -fno-delete-null-pointer-checks
            -fno-PIE -fno-pic -fno-pie -fno-pic -fno-stack-protector -fno-unwind-tables
            -fno-asynchronous-unwind-tables -fno-exceptions -fno-omit-frame-pointer
            -fno-delete-null-pointer-checks
        )

        execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libgcc.a
            OUTPUT_VARIABLE C_LIBGCC_FILE
            OUTPUT_STRIP_TRAILING_WHITESPACE)

        execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libm.a
            OUTPUT_VARIABLE C_LIBM_FILE
            OUTPUT_STRIP_TRAILING_WHITESPACE)

        link_libraries(
            ${C_LIBGCC_FILE}
            ${C_LIBM_FILE}
        )

        include_directories(${ATTESTATION_TOP_DIR}/inc/baremetal)

    endif()

else()

message(STATUS "Posix libc build")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-sanitize=alignment)
    add_link_options(-fsanitize=address,undefined -fno-sanitize=alignment)
endif()

add_definitions(-D_STD_LIBC_)

endif()

if (CMAKE_HOST_SYSTEM_NAME MATCHES Darwin)
    find_program(LIBTOOL libtool
        REQUIRED)
endif()

add_subdirectory(backend)
add_subdirectory(crypto)

add_library(enclave
    STATIC
    enclave.c
    )

target_include_directories(enclave
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

add_dependencies(enclave
    crypto)


add_library(enclave_linux
    STATIC
    enclave.c
    )

target_compile_options(enclave_linux
    PRIVATE
    -nostdlib
)

target_include_directories(enclave_linux
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

target_compile_definitions(enclave_linux
    PRIVATE
    _LINUX_KERNEL_
    )

add_dependencies(enclave_linux
    enclave_linux)

set(BACKEND_LIBRARY ${ATTESTATION_TOP_BUILD_DIR}/backend/mbedtls/library/libmbedcrypto.a)

add_custom_target(backend
    DEPENDS
    mbedtls-config
    mbedcrypto)

add_subdirectory(test)
add_subdirectory(app)

