cmake_minimum_required(VERSION 3.13)

set (HAS_TEST false)

#execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libgcc.a
#    OUTPUT_VARIABLE LIBGCC
#    OUTPUT_STRIP_TRAILING_WHITESPACE)
#
#execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libm.a
#    OUTPUT_VARIABLE LIBM
#    OUTPUT_STRIP_TRAILING_WHITESPACE)
#
#link_libraries(${LIBGCC} ${LIBM})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0 -g)
    add_link_options(-O0 -g)
endif()

#list(APPEND EXTRA_C_SRC
#    ${ATTESTATION_TOP_DIR}/src/baremetal_printf.c
#    )
