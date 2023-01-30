include_directories(${ATTESTATION_TOP_DIR})

add_subdirectory(linux)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_Declare(googlebenchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.7.1)

FetchContent_MakeAvailable(googletest googlebenchmark)

enable_testing()


add_executable(demo_enclave_attestation
    demo_enclave_attestation.c)

target_compile_definitions(demo_enclave_attestation
    PRIVATE
    _STD_LIBC_
    )

target_link_libraries(demo_enclave_attestation
    PRIVATE
    enclave crypto mbedcrypto
    )

include_directories(
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
)

link_libraries(
    enclave crypto mbedcrypto
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
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_ecc_ecdh
    PRIVATE
    enclave crypto mbedcrypto
    GTest::gtest_main
    GTest::gmock
    )

add_executable(test_crypto_rng
    test_crypto_rng.cc
    )

target_compile_definitions(test_crypto_rng
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_rng
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_rng
    PRIVATE
    enclave crypto mbedcrypto
    GTest::gtest_main
    GTest::gmock
    )

add_executable(test_crypto_ecc_ecdsa
    test_crypto_ecc_ecdsa.cc
    )

target_compile_definitions(test_crypto_ecc_ecdsa
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_ecc_ecdsa
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_ecc_ecdsa
    PRIVATE
    enclave crypto mbedcrypto
    GTest::gtest_main
    GTest::gmock
    )

add_executable(test_crypto_md_sha256
    test_crypto_md_sha256.cc
    )

target_compile_definitions(test_crypto_md_sha256
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_md_sha256
    PRIVATE
    ${ATTESTATION_TOP_DIR}
    ${ATTESTATION_TOP_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_md_sha256
    PRIVATE
    enclave crypto mbedcrypto
    GTest::gtest_main
    GTest::gmock
    )

add_executable(test_crypto_rot
    test_crypto_rot.cc
    )

target_compile_definitions(test_crypto_rot
    PRIVATE
    _STD_LIBC_)

add_executable(test_crypto_chacha_poly
    test_crypto_chacha_poly.cc
    )

target_compile_definitions(test_crypto_chacha_poly
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_chacha_poly
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_chacha_poly
    PRIVATE
    enclave crypto mbedcrypto
    GTest::gtest_main
    GTest::gmock
    )

add_executable(test_crypto_random_access_cipher
    test_crypto_random_access_cipher.cc
    )

target_compile_definitions(test_crypto_random_access_cipher
    PRIVATE
    _STD_LIBC_)

target_include_directories(test_crypto_random_access_cipher
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(test_crypto_random_access_cipher
    PRIVATE
    enclave crypto mbedcrypto
    GTest::gtest_main
    GTest::gmock
    )

target_compile_definitions(test_crypto_random_access_cipher
    PRIVATE
    _STD_LIBC_)

include(GoogleTest)
gtest_discover_tests(test_crypto_ecc_ecdh)
gtest_discover_tests(test_crypto_rng)
gtest_discover_tests(test_crypto_ecc_ecdsa)
gtest_discover_tests(test_crypto_md_sha256)
gtest_discover_tests(test_crypto_random_access_cipher)

add_executable(bench_symmetric_cipher
    bench_symmetric_cipher.cc
    )

target_include_directories(bench_symmetric_cipher
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(bench_symmetric_cipher
    PRIVATE
    enclave crypto mbedcrypto
    benchmark::benchmark
    )

add_executable(bench_asymmetric_cipher
    bench_asymmetric_cipher.cc
    )

target_include_directories(bench_asymmetric_cipher
    PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/mbedtls/include
    )

target_link_libraries(bench_asymmetric_cipher
    PRIVATE
    enclave crypto mbedcrypto
    benchmark::benchmark
    )
