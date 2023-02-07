cmake_minimum_required(VERSION 3.13)

message(STATUS "backend: ${BACKEND}")

if (BACKEND STREQUAL "mbedtls")
    include(${ATTESTATION_CMAKE_DIR}/build_mbedtls.cmake)
endif()
