# -- target toolchain
set(LINUX_ARCH "x86")
#--

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")
find_package(KernelHeaders REQUIRED)

set(DRIVER "demo_enclave_linux_driver.ko")
set(DRIVER_SRC
    demo_enclave_linux_driver.c)

add_custom_command(
    OUTPUT demo_enclave_linux_driver.context.tstamp
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_SOURCE_DIR}/crypto/crypto_context_linux_kernel.c
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto_context_linux_kernel.c
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_SOURCE_DIR}/enclave.c
        ${CMAKE_CURRENT_SOURCE_DIR}/enclave.c
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_SOURCE_DIR}/backend/mbedtls
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_SOURCE_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    COMMENT "creating crypto context ..."
    VERBATIM)

if (CROSS_COMPILE)
    set (KBUILD_CMD $(MAKE) -C ${KDIR} M=${CMAKE_CURRENT_BINARY_DIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} src=${CMAKE_CURRENT_SOURCE_DIR} modules)
else()
    set (KBUILD_CMD $(MAKE) -C ${KDIR} M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} modules)
endif()

set(MBEDCRYPTO_SRC
    aes.c
    aesni.c
    aria.c
    asn1parse.c
    asn1write.c
    base64.c
    bignum.c
    camellia.c
    ccm.c
    chacha20.c
    chachapoly.c
    cipher.c
    cipher_wrap.c
    constant_time.c
    cmac.c
    ctr_drbg.c
    des.c
    dhm.c
    ecdh.c
    ecdsa.c
    ecjpake.c
    ecp.c
    ecp_curves.c
    entropy.c
    entropy_poll.c
    error.c
    gcm.c
    hkdf.c
    hmac_drbg.c
    md.c
    md5.c
    memory_buffer_alloc.c
    mps_reader.c
    mps_trace.c
    nist_kw.c
    oid.c
    padlock.c
    pem.c
    pk.c
    pk_wrap.c
    pkcs12.c
    pkcs5.c
    pkparse.c
    pkwrite.c
    platform.c
    platform_util.c
    poly1305.c
    psa_crypto.c
    psa_crypto_aead.c
    psa_crypto_cipher.c
    psa_crypto_client.c
    psa_crypto_driver_wrappers.c
    psa_crypto_ecp.c
    psa_crypto_hash.c
    psa_crypto_mac.c
    psa_crypto_rsa.c
    psa_crypto_se.c
    psa_crypto_slot_management.c
    psa_crypto_storage.c
    psa_its_file.c
    ripemd160.c
    rsa.c
    rsa_alt_helpers.c
    sha1.c
    sha256.c
    sha512.c
    ssl_debug_helpers_generated.c
    threading.c
    timing.c
    version.c
    version_features.c
)

foreach(src ${MBEDCRYPTO_SRC})
    get_filename_component(src_name ${src} NAME_WE)
    list(APPEND MBEDCRYPTO_OBJ mbedtls/library/${src_name}.o)
endforeach()

string(REPLACE ";" " " MBEDCRYPTO_OBJ "${MBEDCRYPTO_OBJ}")

file(
    WRITE
    ${CMAKE_CURRENT_SOURCE_DIR}/Makefile
    "ccflags-y += -D_LINUX_KERNEL_ -DSIZE_MAX=18446744073709551615UL -include ${CMAKE_SOURCE_DIR}/crypto/crypto_context_linux.h -include ${CMAKE_SOURCE_DIR}/backend/mbedtls/include/mbedtls/mbedtls_config.h -I${CMAKE_SOURCE_DIR} -I${CMAKE_SOURCE_DIR}/backend/mbedtls/include -I${CMAKE_SOURCE_DIR}/backend/mbedtls/library -I${CMAKE_CURRENT_BINARY_DIR}/linux\n"
    "ldflags-y += \n"
#    "mbedtls-src = $(wildcard mbedtls/library/*.c)"
#    "mbedtls-obj = $(patsubst %.c, %.o, $(mbedtls-src))"
#    "obj-m += demo_enclave_linux_driver.o\n"
    "obj-m += demo_enclave_linux_driver.o \n"
    "demo_enclave_linux_driver-y += demo_enclave_linux_driver.o crypto_context_linux_kernel.o enclave.o crypto/crypto.o crypto/root_key.o\n"
    "demo_enclave_linux_driver-y += ${MBEDCRYPTO_OBJ}\n"
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
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "creating fake headers ..."
    VERBATIM
)

add_custom_command(OUTPUT ${DRIVER}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/libenclave_linux.a ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/crypto/libcrypto_linux.a ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/backend/mbedtls/library/libmbedcrypto.a ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${DRIVER_SRC} demo_enclave_linux_driver.context.tstamp
        mbedtls_fake_headers.tstamp
    VERBATIM
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

add_custom_target(install_driver DEPENDS "demo_enclave_linux_driver.install.tstamp")

add_custom_command(OUTPUT "demo_enclave_linux_driver.uninstall.tstamp"
    COMMAND sudo modprobe -r demo_enclave_linux_driver
    )

add_custom_target(uninstall_driver DEPENDS "demo_enclave_linux_driver.uninstall.tstamp")
