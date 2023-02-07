cmake_minimum_required(VERSION 3.13)

set (HAS_TEST false)

add_compile_options(
    -nostdlib -nostdinc -ffreestanding -fno-stack-protector
    -fno-common -fno-exceptions -fno-unwind-tables -static
    -fno-asynchronous-unwind-tables -fno-leading-underscore
    -fno-omit-frame-pointer -fno-pic -fno-pie -fno-PIE
)

add_link_options(
    -nostdlib -nostdinc -ffreestanding -fno-stack-protector
    -fno-common -fno-exceptions -fno-unwind-tables -static
    -fno-asynchronous-unwind-tables -fno-leading-underscore
    -fno-omit-frame-pointer -fno-pic -fno-pie -fno-PIE
)

execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libgcc.a
    OUTPUT_VARIABLE LIBGCC
    OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libm.a
    OUTPUT_VARIABLE LIBM
    OUTPUT_STRIP_TRAILING_WHITESPACE)

link_libraries(${LIBGCC} ${LIBM})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0 -g)
    add_link_options(-O0 -g)
endif()

include_directories(
    ${ATTESTATION_TOP_DIR}/inc/baremetal
)

list(APPEND EXTRA_C_SRC
    ${ATTESTATION_TOP_DIR}/src/baremetal_printf.c
    )
