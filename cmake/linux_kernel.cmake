cmake_minimum_required(VERSION 3.13)

set (HAS_TEST false)

if (NOT KDIR)
    execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    find_path(
        KDIR
        include/linux/user.h
        PATHS /lib/modules/${KERNEL_RELEASE}/build
        DOC "Kernel source directory"
        REQUIRED
    )

    message("kdir: /lib/modules/${KERNEL_RELEASE}/build -- ${KDIR}")

    if (NOT KDIR)
        message(FATAL_ERROR "Kernel source directory not found")
    else()
        message(STATUS "Kernel release: ${KERNEL_RELEASE}")
        message(STATUS "Kernel source directory: ${KDIR}")
    endif()
endif()

if (NOT KARCH)
    execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE KARCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    message(STATUS "Kernel architecture: ${KARCH}")
endif()

set (KINC
    ${KDIR}/include
    ${KDIR}/arch/${KARCH}/include
    CACHE PATH "Kernel include directory"
    )

if (KDIR AND KINC)
    set (KDIR_FOUND true CACHE BOOL "Kernel source directory found")
else()
    set (KDIR_FOUND false CACHE BOOL "Kernel source directory found")
endif()

mark_as_advanced(KDIR_FOUND)

set (MODULE_SRC ${ATTESTATION_BUILD_DIR}/module)
set (MODULE_OBJ ${MODULE_SRC}/obj)

add_custom_command(
    OUTPUT linux_kernel_context.tstamp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${MODULE_SRC}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${MODULE_OBJ}

    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/src ${ATTESTATION_BUILD_DIR}/module/src
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/inc ${ATTESTATION_BUILD_DIR}/module/inc
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/backend/${BACKEND} ${ATTESTATION_BUILD_DIR}/module/${BACKEND}
    COMMAND ${CMAKE_COMMAND} -E touch linux_kernel_context.tstamp

    DEPENDS ${ATTESTATION_TOP_DIR}/cmake/linux_kernel.cmake
    WORKING_DIRECTORY ${ATTESTATION_BUILD_DIR}
    COMMENT "Creating for kernel module building environment ..."
    VERBATIM
)

add_custom_target(
    linux_kernel_context
    DEPENDS linux_kernel_context.tstamp
)

add_custom_command(
    OUTPUT mbedtls_fake_headers.tstamp
    COMMAND ${CMAKE_COMMAND} -E make_directory -p ${MODULE_SRC}/linux
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/assert.h
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/limits.h
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/stdint.h
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/stdio.h
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/stdlib.h
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/string.h
    COMMAND ${CMAKE_COMMAND} -E touch ${MODULE_SRC}/linux/time.h
    COMMAND ${CMAKE_COMMAND} -E touch mbedtls_fake_headers.tstamp
    WORKING_DIRECTORY ${MODULE_SRC}
    COMMENT "creating fake headers ..."
    VERBATIM
)

add_custom_target(
    mbedtls_fake_headers
    DEPENDS mbedtls_fake_headers.tstamp
)

if (CROSS_COMPILE)
    set (BUILD_CMD $(MAKE)
            -C ${KDIR}
            src=${MODULE_SRC}
            M=${MODULE_OBJ}
            ARCH=${KARCH}
            CROSS_COMPILE=${CROSS_COMPILE}
        )
else()
    set (BUILD_CMD $(MAKE)
            -C ${KDIR}
            src=${MODULE_SRC}
            M=${MODULE_OBJ}
            ARCH=${KARCH}
        )
endif()

include(${ATTESTATION_TOP_DIR}/cmake/linux_kernel_extra.cmake)

add_subdirectory(backend)
add_subdirectory(src)

get_target_property(
    BACKEND_SRC
    mbedcrypto
    SOURCES
)
message(STATUS "backend sources list: ${BACKEND_SRC}")

foreach (src ${BACKEND_SRC})
    get_filename_component(src_name ${src} NAME_WE)
    list (APPEND BACKEND_OBJ ${BACKEND}/library/${src_name}.o)
endforeach()

string(REPLACE ";" " " BACKEND_OBJ "${BACKEND_OBJ}")

get_target_property(
    ABSTRACT_SRC
    crypto_abstract
    SOURCES
)
message(STATUS "crypto abstraction layer list: ${ABSTRACT_SRC}")

foreach (src ${ABSTRACT_SRC})
    get_filename_component(src_name ${src} NAME_WE)
    list (APPEND ABSTRACT_OBJ src/${src_name}.o)
endforeach()

string(REPLACE ";" " " ABSTRACT_OBJ "${ABSTRACT_OBJ}")

file(
    WRITE
    ${MODULE_SRC}/Kbuild
    "obj-m += dummy_main.o \n"
    "dummy_main-y += ${BACKEND_OBJ} \n"
    "dummy_main-y += ${ABSTRACT_OBJ} \n"
    "ccflags-y += -std=gnu99 \n"
    "ccflags-y += -Wno-declaration-after-statement \n"
    "ccflags-y += -Wframe-larger-than=4096 -ffreestanding \n"
    "ccflags-y += -D_LINUX_KERNEL_ \n"
    "ccflags-y += -DLINUX_KERNEL \n"
    "ccflags-y += -include ${MODULE_SRC}/inc/primitives_linux_kernel.h \n"
    "ccflags-y += -include ${MODULE_SRC}/${BACKEND}/include/mbedtls/mbedtls_config.h \n"
    "ccflags-y += -I${MODULE_SRC}/linux/ \n"
    "ccflags-y += -I${MODULE_SRC}/inc/ \n"
    "ccflags-y += -I${MODULE_SRC}/${BACKEND}/include \n"
    "ccldflags-y += -Wl,--build-id=none \n"
    )

add_custom_command(
    OUTPUT dummy_main.ko
    COMMAND ${BUILD_CMD} modules
    DEPENDS backend-prebuild mbedtls_fake_headers linux_kernel_context
    WORKING_DIRECTORY ${MODULE_SRC}
    COMMENT "Building kernel module ..."
    VERBATIM
)

add_custom_target(
    dummy_module
    DEPENDS dummy_main.ko
)

add_custom_command(
    OUTPUT dummy_main.ko.clean
    COMMAND ${BUILD_CMD} clean
    WORKING_DIRECTORY ${MODULE_SRC}
    COMMENT "Cleaning kernel module ..."
    VERBATIM
)

add_custom_target(
    dummy_module_clean
    DEPENDS dummy_main.ko.clean
)

#
# only for cmake symbol search
#
add_executable(
    dummy_module_symbols
    ${ATTESTATION_TOP_DIR}/src/dummy_module.c
    EXCLUDE_FROM_ALL
)

target_link_libraries(
    dummy_module_symbols
    crypto_abstract
    mbedcrypto
)

#
# --
#
