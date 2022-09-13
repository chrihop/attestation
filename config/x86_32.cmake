include(CMakeForceCompiler)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_SYSTEM_VERSION 1)

set(CMAKE_SYSTEM_PROCESSOR "x86_64")
find_program(GCC gcc)
find_program(GXX g++)
set(CMAKE_C_COMPILER "${GCC}")
set(CMAKE_CXX_COMPILER "${GXX}")

# keep every function in a separate section, this allows linker to discard unused ones
set(TOOLCHAIN_C_FLAGS "-m32 -msoft-float")
set(TOOLCHAIN_C_FLAGS "${TOOLCHAIN_C_FLAGS} -fno-strict-aliasing -fno-stack-protector -fno-mudflap -fno-builtin")
set(TOOLCHAIN_C_FLAGS "${TOOLCHAIN_C_FLAGS} -fno-builtin -fshort-enums")
set(TOOLCHAIN_C_FLAGS "${TOOLCHAIN_C_FLAGS} -DENABLE_RETARGET")

set(TOOLCHAIN_C_FLAGS_DEBUG "-O0 -g -ggdb")
set(TOOLCHAIN_C_FLAGS_RELEASE "-O3")

include_directories(${PROJECT_SOURCE_DIR}/port)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TOOLCHAIN_C_FLAGS}")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} ${TOOLCHAIN_C_FLAGS} ${TOOLCHAIN_C_FLAGS_RELEASE}")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} ${TOOLCHAIN_C_FLAGS} ${TOOLCHAIN_C_FLAGS_DEBUG}")

# link_directories(
#     <path to linker file>
# )

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nolibc -nostdlib -Wl,--gc-sections")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --specs=nosys.specs")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T<linker file name>")
set(CMAKE_CROSSCOMPILING ON)
