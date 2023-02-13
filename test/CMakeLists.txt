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
    GIT_TAG 5be0f95443d4816811bfaea2b05258e7b0528064
)
set (ELFIO_BUILD_TESTS OFF)
set (ELFIO_BUILD_EXAMPLES OFF)
FetchContent_MakeAvailable(elfio)
#
#FetchContent_Declare(
#    yaml_cpp
#    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
#    GIT_TAG 1b50109f7bea60bd382d8ea7befce3d2bd67da5f
#)
#set (YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
#set (YAML_CPP_BUILD_TOOLS OFF  CACHE BOOL "" FORCE)
#set (YAML_CPP_BUILD_CONTRIB OFF  CACHE BOOL "" FORCE)
#set (YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
#set (YAML_CPP_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
#set (YAML_CPP_FORMAT_SOURCE OFF CACHE BOOL "" FORCE)
#FetchContent_MakeAvailable(yaml_cpp)

add_executable(test_enclave_platform_loader
    test_enclave_platform_loader.cc)

add_custom_command(
    TARGET test_enclave_platform_loader
    POST_BUILD
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/sample_enclave_user.trust.yaml
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/sample_enclave_user.trust.yaml
        ${CMAKE_CURRENT_BINARY_DIR}/sample_enclave_user.trust.yaml
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Copying sample_enclave_user.trust.yaml"
    VERBATIM
)

target_link_libraries(test_enclave_platform_loader
    PRIVATE
    elfio::elfio
    )

target_include_directories(test_enclave_platform_loader
    PRIVATE
    ${YAML_CPP_SOURCE_DIR}/include)

add_dependencies(
    test_enclave_platform_loader
    sample_enclave
)

add_executable(test_enclave_platform_attestation
    test_enclave_platform_attestation.cc)

add_custom_target(
    test_suites
    DEPENDS
    test_psa_symmetric_cipher
    test_psa_asymmetric_cipher
    test_psa_kd
    test_psa_hash
    test_mbedtls_abstraction
    test_enclave_platform_loader
    test_enclave_platform_attestation
)

# --
include(GoogleTest)
gtest_discover_tests(test_psa_symmetric_cipher)
gtest_discover_tests(test_psa_asymmetric_cipher)
gtest_discover_tests(test_psa_kd)
gtest_discover_tests(test_psa_hash)
gtest_discover_tests(test_mbedtls_abstraction)
gtest_discover_tests(test_enclave_platform_loader)
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
