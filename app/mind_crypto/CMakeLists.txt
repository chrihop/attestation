# -- target toolchain
set(LINUX_ARCH "x86")
#--

list(APPEND CMAKE_MODULE_PATH "${ATTESTATION_TOP_DIR}")
find_package(KernelHeaders REQUIRED)

set(DRIVER_NAME "mind_crypto")
set(DRIVER "${DRIVER_NAME}.ko")
set(DRIVER_SRC
    mind_crypto_main.c)

add_custom_command(
    OUTPUT ${DRIVER_NAME}.context.tstamp
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

foreach(src ${DRIVER_SRC})
    get_filename_component(src_name ${src} NAME_WE)
    list(APPEND DRIVER_OBJ ${src_name}.o)
endforeach()

string(REPLACE ";" " " DRIVER_OBJ "${DRIVER_OBJ}")

file(
    WRITE
    ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
    "obj-m += ${DRIVER_NAME}.o\n"
    "${DRIVER_NAME}-y += ${DRIVER_OBJ}\n"
    "${DRIVER_NAME}-y += crypto_context_linux_kernel.o enclave.o crypto/crypto.o crypto/root_key.o\n"
    "${DRIVER_NAME}-y += ${MBEDCRYPTO_OBJ}\n"
    "ccflags-y += -std=gnu99 -Wno-declaration-after-statement -Wframe-larger-than=4096\n"
    "ccflags-y += -ffreestanding -D_LINUX_KERNEL_\n"
    "ccflags-y += -include ${ATTESTATION_TOP_DIR}/crypto/crypto_context_linux.h\n"
    "ccflags-y += -include ${ATTESTATION_TOP_DIR}/backend/mbedtls/include/mbedtls/mbedtls_config.h\n"
    "ccflags-y += -I${ATTESTATION_TOP_DIR} -I${ATTESTATION_TOP_DIR}/backend/mbedtls/include -I${ATTESTATION_TOP_DIR}/backend/mbedtls/library\n"
    "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/include\n"
    "ldflags-y += \n"
)

add_custom_command(OUTPUT ${DRIVER}
    COMMAND ${KBUILD_CMD} modules
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${DRIVER_SRC}
        mbedtls-config
        ${DRIVER_NAME}.context.tstamp
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
    mind_crypto_main.c
)

target_include_directories(${DRIVER}.objs
    PRIVATE
    ${KINC}
    ${CMAKE_SOURCE_DIR}
)

target_compile_options(${DRIVER}.objs
    PRIVATE
    -std=gnu99 -Wno-declaration-after-statement -Wframe-larger-than=4096
    -ffreestanding -D_LINUX_KERNEL_
    )

target_compile_definitions(${DRIVER}.objs
    PRIVATE
    _LINUX_KERNEL_
)

add_custom_target(${DRIVER_NAME}
    DEPENDS ${DRIVER}
    )

add_custom_command(OUTPUT "${DRIVER_NAME}.install.tstamp"
    COMMAND sudo insmod ${DRIVER}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${DRIVER}
    VERBATIM
    )

add_custom_target(${DRIVER_NAME}-install DEPENDS "${DRIVER_NAME}.install.tstamp")

add_custom_command(OUTPUT "${DRIVER_NAME}.uninstall.tstamp"
    COMMAND sudo rmmod ${DRIVER_NAME}
    )

add_custom_target(${DRIVER_NAME}-uninstall DEPENDS "${DRIVER_NAME}.uninstall.tstamp")
