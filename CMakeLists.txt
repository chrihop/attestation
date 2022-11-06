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

if (NOT BAREMETAL)

message(STATUS "Posix libc build")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-sanitize=alignment)
    add_link_options(-fsanitize=address,undefined -fno-sanitize=alignment)
endif()

add_definitions(-D_STD_LIBC_)

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

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

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
    DEPENDS mbedcrypto)
#
#if (CMAKE_HOST_SYSTEM_NAME MATCHES Linux)
#
#configure_file(
#    ${ATTESTATION_TOP_DIR}/libenclave.mri.in
#    ${ATTESTATION_TOP_BUILD_DIR}/libenclave.mri
#)
#
#add_custom_command(
#    OUTPUT libenclave.a.tstamp
#    DEPENDS enclave crypto backend
#    COMMAND ${CMAKE_AR} -M < libenclave.mri
#    COMMAND ${CMAKE_COMMAND} -E touch libenclave.a.tstamp
#    WORKING_DIRECTORY ${ATTESTATION_TOP_BUILD_DIR}
#    COMMENT "Merge generated libraries ..."
#    VERBATIM
#)
#
#else()
#
#add_custom_command(
#    OUTPUT libenclave.a.tstamp
#    DEPENDS enclave crypto backend
#    COMMAND ${LIBTOOL} -static -o libenclave_merged.a
#            libenclave.a crypto/libcrypto.a
#            ${BACKEND_LIBRARY}
#    COMMAND ${CMAKE_COMMAND} -E rename libenclave_merged.a libenclave.a
#    COMMAND ${CMAKE_COMMAND} -E touch libenclave.a.tstamp
#    WORKING_DIRECTORY ${ATTESTATION_TOP_BUILD_DIR}
#    COMMENT "Merge generated libraries ..."
#    VERBATIM
#)
#
#endif()
#
#add_custom_target(enclave-merge
#    DEPENDS
#    libenclave.a.tstamp)

add_subdirectory(test)
