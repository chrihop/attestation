#
# build a dummy elf file
#
include(FindPython3)

add_executable(
    sample_enclave_user
    sample_enclave_user.c
)

target_compile_options(sample_enclave_user
    PRIVATE
    -O2 -g0
    )

target_link_libraries(sample_enclave_user
    PRIVATE
    crypto_abstract
    mbedcrypto
    enclave_common
)

set (ROOT_KEY                 ${ATTESTATION_TEST_DIR}/root_key.pem)
set (DEVELOPER_KEY            ${ATTESTATION_TEST_DIR}/developer_key.pem)
set (DEVELOPER_TRUST          ${ATTESTATION_TEST_DIR}/sample_enclave_user.trust.yaml)
set (DEVELOPER_IDENT          ${ATTESTATION_BUILD_DIR}/developer_id.pem)
set (DEVELOPER_CERT           ${ATTESTATION_BUILD_DIR}/developer_cert.json)

add_custom_command(
    OUTPUT ${DEVELOPER_IDENT}
    COMMAND ${PYTHON} ${ATTESTATION_MISC_DIR}/key.py --command extract
        --out ${DEVELOPER_IDENT}
        --keypair ${DEVELOPER_KEY}
    WORKING_DIRECTORY ${ATTESTATION_BUILD_DIR}
    DEPENDS ${DEVELOPER_KEY}
)

add_custom_command(
    OUTPUT ${DEVELOPER_CERT}
    COMMAND ${PYTHON} ${ATTESTATION_MISC_DIR}/key.py --command authorize
        --out ${DEVELOPER_CERT}
        --keypair ${ROOT_KEY}
        --pubkey ${DEVELOPER_IDENT}
    WORKING_DIRECTORY ${ATTESTATION_BUILD_DIR}
    DEPENDS ${DEVELOPER_IDENT}
)

find_path(BINUTILS
    NAMES ${CROSS_COMPILE}objdump
    REQUIRED
)

add_custom_command(
    OUTPUT ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user.signed
    COMMAND ${PYTHON} ${ATTESTATION_MISC_DIR}/key.py --command trust
        --out ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user.trust.signed
        --keypair ${DEVELOPER_KEY}
        --trust ${DEVELOPER_TRUST}
        --cert ${DEVELOPER_CERT}
        --elf ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user
        --binutils ${BINUTILS}/
    COMMAND ${PYTHON} ${ATTESTATION_MISC_DIR}/key.py --command sign
        --out ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user.signed
        --keypair ${DEVELOPER_KEY}
        --cert ${DEVELOPER_CERT}
        --elf ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user.trust.signed
        --binutils ${BINUTILS}/
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user.signed
        ${ATTESTATION_BUILD_DIR}/sample_enclave_user.signed
    WORKING_DIRECTORY ${ATTESTATION_BUILD_DIR}
    DEPENDS ${DEVELOPER_CERT} sample_enclave_user
        ${ATTESTATION_MISC_DIR}/key.py
)

add_custom_target(
    sample_enclave
    DEPENDS ${ATTESTATION_BUILD_DIR}/test/sample_enclave_user.signed
)
