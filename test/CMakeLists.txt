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
