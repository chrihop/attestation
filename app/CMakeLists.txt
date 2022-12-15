cmake_minimum_required(VERSION 3.0)

option(BUILD_MIND_CRYPTO "Build Mind Crypto Driver" ON)

if(BUILD_MIND_CRYPTO)
    add_subdirectory(mind_crypto)
endif()
