include_directories(${CMAKE_SOURCE_DIR})

add_executable(demo_enclave_attestation
    demo_enclave_attestation.c)

target_compile_definitions(demo_enclave_attestation
    PRIVATE
    _STD_LIBC_
)

target_link_libraries(demo_enclave_attestation
    PRIVATE
    enclave
)

add_dependencies(demo_enclave_attestation
    enclave-merge
)

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
)

link_libraries(
    enclave
    GTest::gtest_main
    GTest::gmock
)

add_executable(test_crypto_ecc_ecdh
  test_crypto_ecc_ecdh.cc
)

target_compile_definitions(test_crypto_ecc_ecdh
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_ecc_ecdh
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_ecc_ecdh
    PRIVATE
    enclave
    GTest::gtest_main
    GTest::gmock
)

add_dependencies(test_crypto_ecc_ecdh
    enclave-merge
)

add_executable(test_crypto_rng
  test_crypto_rng.cc
)

target_compile_definitions(test_crypto_rng
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_rng
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_rng
    PRIVATE
    enclave
    GTest::gtest_main
    GTest::gmock
)

add_dependencies(test_crypto_rng
    enclave-merge
)

add_executable(test_crypto_ecc_ecdsa
  test_crypto_ecc_ecdsa.cc
)

target_compile_definitions(test_crypto_ecc_ecdsa
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_ecc_ecdsa
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_ecc_ecdsa
    PRIVATE
    enclave
    GTest::gtest_main
    GTest::gmock
)

add_dependencies(test_crypto_ecc_ecdsa
    enclave-merge
)

add_executable(test_crypto_md_sha256
  test_crypto_md_sha256.cc
)

target_compile_definitions(test_crypto_md_sha256
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_md_sha256
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_md_sha256
    PRIVATE
    enclave
    GTest::gtest_main
    GTest::gmock
)

add_dependencies(test_crypto_md_sha256
    enclave-merge
)

add_executable(test_crypto_rot
  test_crypto_rot.cc
)

target_compile_definitions(test_crypto_rot
    PRIVATE
    _STD_LIBC_)

add_dependencies(test_crypto_rot
    enclave-merge
)

include(GoogleTest)
gtest_discover_tests(test_crypto_ecc_ecdh)
gtest_discover_tests(test_crypto_rng)
gtest_discover_tests(test_crypto_ecc_ecdsa)
gtest_discover_tests(test_crypto_md_sha256)
