cmake_minimum_required(VERSION 3.13)

include(FetchContent)

FetchContent_declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        release-1.12.0
)

set (gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.7.1
)

FetchContent_MakeAvailable(googletest googlebenchmark)
enable_testing()

link_libraries(
    crypto_abstract
    mbedcrypto
    GTest::gtest_main
    GTest::gmock
)

include_directories(
    ${ATTESTATION_BACKEND_DIR}/${BACKEND}/include
    ${ATTESTATION_TOP_DIR}/inc
)

#
# Unit tests
#

add_executable(test_psa_symmetric_cipher
    test_psa_symmetric_cipher.cc)

add_executable(test_psa_asymmetric_cipher
    test_psa_asymmetric_cipher.cc)

add_executable(test_psa_kd
    test_psa_kd.cc)

add_executable(test_psa_hash
    test_psa_hash.cc)

add_executable(test_mbedtls_abstraction
    test_mbedtls_abstraction.cc)
# --
include(GoogleTest)
gtest_discover_tests(test_psa_symmetric_cipher)
gtest_discover_tests(test_psa_asymmetric_cipher)
gtest_discover_tests(test_psa_kd)
gtest_discover_tests(test_psa_hash)
gtest_discover_tests(test_mbedtls_abstraction)
# --

#
# Benchmarks
#

link_libraries(
    benchmark::benchmark
)

add_executable(bench_psa_symmetric_cipher
    bench_psa_symmetric_cipher.cc)


add_executable(bench_mbedtls_abstraction
    bench_mbedtls_abstraction.cc)
