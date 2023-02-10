cmake_minimum_required(VERSION 3.13)

include(${ATTESTATION_TOP_DIR}/cmake/enclave_user_build.cmake)

link_libraries(
    enclave_platform
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

FetchContent_Declare(
    elfio
    GIT_REPOSITORY https://github.com/serge1/ELFIO.git
    GIT_TAG Release_3.11
)
set (ELFIO_BUILD_TESTS OFF)
set (ELFIO_BUILD_EXAMPLES OFF)
FetchContent_MakeAvailable(elfio)

add_executable(test_enclave_platform
    test_enclave_platform.cc)

target_link_libraries(test_enclave_platform
    PRIVATE
    elfio::elfio)

add_dependencies(
    test_enclave_platform
    sample_enclave
)

add_custom_target(
    test_suites
    DEPENDS
    test_psa_symmetric_cipher
    test_psa_asymmetric_cipher
    test_psa_kd
    test_psa_hash
    test_mbedtls_abstraction
    test_enclave_platform
)

# --
include(GoogleTest)
gtest_discover_tests(test_psa_symmetric_cipher)
gtest_discover_tests(test_psa_asymmetric_cipher)
gtest_discover_tests(test_psa_kd)
gtest_discover_tests(test_psa_hash)
gtest_discover_tests(test_mbedtls_abstraction)
gtest_discover_tests(test_enclave_platform)
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


#
#
#
