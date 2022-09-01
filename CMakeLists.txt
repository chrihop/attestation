cmake_minimum_required(VERSION 3.13)

project(attestation)
set(CMAKE_C_STANDARD 11)

find_program(LIBTOOL libtool
    REQUIRED)

add_subdirectory(crypto)

add_library(enclave
    STATIC
    enclave.c
    )

target_include_directories(enclave
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    )

target_compile_definitions(enclave
    PRIVATE
    _STD_LIBC_
    )

add_dependencies(enclave
    crypto)

if (CMAKE_BUILD_TYPE MATCHES DEBUG)
    set(BACKEND_LIBRARY ${CMAKE_SOURCE_DIR}/backend/${CMAKE_SYSTEM_PROCESSOR}/libmbedcrypto_debug.a)
else ()
    set(BACKEND_LIBRARY ${CMAKE_SOURCE_DIR}/backend/${CMAKE_SYSTEM_PROCESSOR}/libmbedcrypto_release.a)
endif ()

configure_file(
    ${CMAKE_SOURCE_DIR}/libenclave.mri.in
    ${CMAKE_BINARY_DIR}/libenclave.mri
)

add_custom_command(TARGET enclave
    POST_BUILD
    COMMAND ${CMAKE_AR} -M < libenclave.mri
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Merge generated libraries ..."
    VERBATIM
)

add_subdirectory(test)
