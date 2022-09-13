# build tools
set(CMAKE_ASM_COMPILER as)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_OBJCOPY objcopy)
set(CMAKE_RANLIB ranlib)
set(CMAKE_STRIP strip)

# target platform
set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_SYSTEM_PROCESSOR "x86_64")

# flags
set(CMAKE_C_FLAGS "")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -ggdb -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_EXE_LINKER_FLAGS "")

# sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# host build
set(ARCH "x86")

# Optionally reduce compiler sanity check when cross-compiling.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
