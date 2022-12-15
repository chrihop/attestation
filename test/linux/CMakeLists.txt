# -- target toolchain
set(LINUX_ARCH "x86")
#--

list(APPEND CMAKE_MODULE_PATH "${ATTESTATION_TOP_DIR}")
find_package(KernelHeaders REQUIRED)

set(DRIVER_NAME "attestation")
set(DRIVER "${DRIVER_NAME}.ko")
set(DRIVER_SRC
    demo_enclave_linux_driver.c)

add_custom_command(
    OUTPUT demo_enclave_linux_driver.context.tstamp
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/crypto/crypto_context_linux_kernel.c
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto_context_linux_kernel.c
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/enclave.c
        ${CMAKE_CURRENT_SOURCE_DIR}/enclave.c
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/backend/mbedtls
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_TOP_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    COMMENT "creating crypto context ..."
    VERBATIM)

if (CROSS_COMPILE)
    set (KBUILD_CMD $(MAKE) -C ${KDIR} M=${CMAKE_CURRENT_BINARY_DIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} src=${CMAKE_CURRENT_SOURCE_DIR})
else()
    set (KBUILD_CMD $(MAKE) -C ${KDIR} M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})
endif()

get_target_property(MBEDCRYPTO_SRC mbedcrypto SOURCES)

message(STATUS "mbedcrypto sources: ${MBEDCRYPTO_SRC}")

foreach(src ${MBEDCRYPTO_SRC})
    get_filename_component(src_name ${src} NAME_WE)
    list(APPEND MBEDCRYPTO_OBJ mbedtls/library/${src_name}.o)
endforeach()

string(REPLACE ";" " " MBEDCRYPTO_OBJ "${MBEDCRYPTO_OBJ}")

file(
    WRITE
    ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
    "obj-m += attestation.o \n"
    "attestation-y += demo_enclave_linux_driver.o crypto_context_linux_kernel.o enclave.o crypto/crypto.o crypto/root_key.o\n"
    "attestation-y += ${MBEDCRYPTO_OBJ}\n"
    "ccflags-y += -std=gnu99 -Wno-declaration-after-statement -Wframe-larger-than=4096 -ffreestanding -D_LINUX_KERNEL_ -include ${ATTESTATION_TOP_DIR}/crypto/crypto_context_linux.h -include ${ATTESTATION_TOP_DIR}/backend/mbedtls/include/mbedtls/mbedtls_config.h -I${ATTESTATION_TOP_DIR} -I${ATTESTATION_TOP_DIR}/backend/mbedtls/include -I${ATTESTATION_TOP_DIR}/backend/mbedtls/library -I${CMAKE_CURRENT_SOURCE_DIR}/include\n"
    "ldflags-y += \n"
)

add_custom_command(
    OUTPUT mbedtls_fake_headers.tstamp
    COMMAND ${CMAKE_COMMAND} -E make_directory -p ${CMAKE_CURRENT_BINARY_DIR}/linux
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/assert.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/limits.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/stdint.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/stdio.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/stdlib.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/string.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/linux/time.h
    COMMAND ${CMAKE_COMMAND} -E touch mbedtls_fake_headers.tstamp
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "creating fake headers ..."
    VERBATIM
)

add_custom_command(OUTPUT ${DRIVER}
    COMMAND ${KBUILD_CMD} modules
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${DRIVER_SRC}
        mbedtls-config
        demo_enclave_linux_driver.context.tstamp
        mbedtls_fake_headers.tstamp
        mbedtls-patch
    COMMENT "building driver ..."
    VERBATIM
    )

add_custom_command(OUTPUT ${DRIVER}.clean.stamp
    COMMAND ${KBUILD_CMD} clean
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "cleaning driver ..."
    VERBATIM
    )

add_custom_target(${DRIVER_NAME}-clean
    DEPENDS ${DRIVER}.clean.stamp
    )


add_library(${DRIVER}.objs
    demo_enclave_linux_driver.c
)

target_include_directories(${DRIVER}.objs
    PRIVATE
    ${KINC}
    ${CMAKE_SOURCE_DIR}
)

target_compile_definitions(${DRIVER}.objs
    PRIVATE
    _LINUX_KERNEL_
)

add_custom_target(demo_enclave_linux_driver
    DEPENDS ${DRIVER}
    )

add_custom_command(OUTPUT "demo_enclave_linux_driver.install.tstamp"
    COMMAND sudo insmod ${DRIVER}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${DRIVER}
    VERBATIM
    )

add_custom_target(${DRIVER_NAME}-install DEPENDS "demo_enclave_linux_driver.install.tstamp")

add_custom_command(OUTPUT "demo_enclave_linux_driver.uninstall.tstamp"
    COMMAND sudo rmmod attestation
    )

add_custom_target(${DRIVER_NAME}-uninstall DEPENDS "demo_enclave_linux_driver.uninstall.tstamp")
