include(CMakeForceCompiler)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_SYSTEM_VERSION 1)

set(CMAKE_SYSTEM_PROCESSOR "armv7")
find_program(GCC $ENV{ARM}/bin/arm-none-eabi-gcc)
find_program(GXX $ENV{ARM}/bin/arm-none-eabi-g++)
set(CMAKE_C_COMPILER "${GCC}")
set(CMAKE_CXX_COMPILER "${GXX}")

# keep every function in a separate section, this allows linker to discard unused ones
set(TOOLCHAIN_C_FLAGS "-march=armv8-a+crc -mtune=cortex-a53 -mfloat-abi=softfp -mno-unaligned-access -mno-thumb-interwork")
set(TOOLCHAIN_C_FLAGS "${TOOLCHAIN_C_FLAGS} -fno-strict-aliasing")
set(TOOLCHAIN_C_FLAGS "${TOOLCHAIN_C_FLAGS} -fshort-enums -ffreestanding -fno-stack-protector -fno-pie -no-pie")
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

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -nolibc -nostdlib -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --specs=nosys.specs")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T<linker file name>")
set(CMAKE_CROSSCOMPILING ON)
