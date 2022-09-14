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

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-sanitize=alignment)
    add_link_options(-fsanitize=address,undefined -fno-sanitize=alignment)
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
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_compile_definitions(enclave
    PRIVATE
    _STD_LIBC_
    )

add_dependencies(enclave
    crypto)

#if (CMAKE_BUILD_TYPE MATCHES DEBUG)
#    set(BACKEND_LIBRARY ${CMAKE_SOURCE_DIR}/backend/${CMAKE_SYSTEM_PROCESSOR}/libmbedcrypto_debug.a)
#else ()
#    set(BACKEND_LIBRARY ${CMAKE_SOURCE_DIR}/backend/${CMAKE_SYSTEM_PROCESSOR}/libmbedcrypto_release.a)
#endif ()

set(BACKEND_LIBRARY ${CMAKE_BINARY_DIR}/backend/mbedtls/library/libmbedcrypto.a)

add_custom_target(backend
    DEPENDS mbedcrypto)

if (CMAKE_HOST_SYSTEM_NAME MATCHES Linux)

configure_file(
    ${CMAKE_SOURCE_DIR}/libenclave.mri.in
    ${CMAKE_BINARY_DIR}/libenclave.mri
)

add_custom_command(
    OUTPUT libenclave.a.tstamp
    DEPENDS enclave crypto backend
    COMMAND ${CMAKE_AR} -M < libenclave.mri
    COMMAND ${CMAKE_COMMAND} -E touch libenclave.a.tstamp
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Merge generated libraries ..."
    VERBATIM
)

else()

add_custom_command(
    OUTPUT libenclave.a.tstamp
    DEPENDS enclave crypto backend
    COMMAND ${LIBTOOL} -static -o libenclave_merged.a
            libenclave.a crypto/libcrypto.a
            ${BACKEND_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E rename libenclave_merged.a libenclave.a
    COMMAND ${CMAKE_COMMAND} -E touch libenclave.a.tstamp
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Merge generated libraries ..."
    VERBATIM
)

endif()

add_custom_target(enclave-merge
    DEPENDS
    libenclave.a.tstamp)

add_subdirectory(test)
