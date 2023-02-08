cmake_minimum_required(VERSION 3.13)

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE HOST_ARCH
)

string (STRIP ${HOST_ARCH} HOST_ARCH)

project(attestation)

set (CMAKE_C_STANDARD 11)
set (CMAKE_CXX_STANDARD 17)

set (BUILD_FOR "posix" CACHE STRING "The target system to link with")
set_property(CACHE BUILD_FOR PROPERTY STRINGS
    "posix" "baremetal" "certikos_kernel" "certikos_user"
    "linux_kernel")

set (BACKEND "mbedtls" CACHE STRING "Backend crypto library to use")
set_property(CACHE BACKEND PROPERTY STRINGS "mbedtls"
    # "openssl" "wolfssl"
    )

include(CheckCCompilerFlag)
include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

set (ATTESTATION_TOP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set (ATTESTATION_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})

set (ATTESTATION_BACKEND_DIR ${ATTESTATION_TOP_DIR}/backend)
set (ATTESTATION_BACKEND_BUILD_DIR ${ATTESTATION_BUILD_DIR}/backend)

set (ATTESTATION_TEST_DIR ${ATTESTATION_TOP_DIR}/test)
set (ATTESTATION_TEST_BUILD_DIR ${ATTESTATION_BUILD_DIR}/test)

set (ATTESTATION_CMAKE_DIR ${ATTESTATION_TOP_DIR}/cmake)

list(APPEND CMAKE_MODULE_PATH ${ATTESTATION_CMAKE_DIR})

if (BUILD_FOR STREQUAL "posix")
    message (STATUS "POSIX Libc build")
    set (HAS_TEST true)
    add_compile_definitions(POSIX_LIBC)
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_definitions(DEBUG_BUILD)
        add_compile_options(-O0 -g -ggdb)
        add_compile_options(-fsanitize=address,undefined -fno-sanitize=alignment)
        add_link_options(-fsanitize=address,undefined -fno-sanitize=alignment)
        add_link_options(-rdynamic)
    endif()
elseif (BUILD_FOR STREQUAL "baremetal")
    message(STATUS "Baremetal build")
    add_compile_definitions(BAREMETAL)
    include(${ATTESTATION_TOP_DIR}/cmake/baremetal.cmake)
elseif (BUILD_FOR STREQUAL "certikos_kernel")
    message(STATUS "CertiKOS kernel build")
    add_compile_definitions(CERTIKOS_KERNEL)
    include(certikos_kernel.cmake)
elseif (BUILD_FOR STREQUAL "certikos_user")
    message(STATUS "CertiKOS user build")
    add_compile_definitions(CERTIKOS_USER)
    include(certikos_user.cmake)
elseif (BUILD_FOR STREQUAL "linux_kernel")
    message(STATUS "Linux kernel build")
    add_compile_definitions(LINUX_KERNEL)
    add_compile_definitions(_LINUX_KERNEL_)
    include(${ATTESTATION_TOP_DIR}/cmake/linux_kernel.cmake)
else ()
    message(FATAL_ERROR "Unknown build target: cmake .. -DBUILD_FOR=<posix|baremetal|certikos|linux_kernel>")
endif()

if (BACKEND STREQUAL "mbedtls")
    add_compile_definitions(BACKEND_MBEDTLS)
else()
    message(FATAL_ERROR "Unknown backend: cmake .. -DBACKEND=<mbedtls|>")
endif()

if (NOT BUILD_FOR STREQUAL "linux_kernel")
    add_subdirectory(backend)
    add_subdirectory(src)
endif()

if (HAS_TEST)
    include(${ATTESTATION_CMAKE_DIR}/testing.cmake)
    add_subdirectory(test)
endif()
