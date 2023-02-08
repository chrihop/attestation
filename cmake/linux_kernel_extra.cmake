#
# only for symbol search, not for building
#
include_directories(
    ${ATTESTATION_TOP_DIR}/inc
    ${ATTESTATION_TOP_DIR}/backend/${BACKEND}/include
    ${KDIR}/arch/x86/include
    ${KDIR}/arch/x86/include/generated
    ${KDIR}/include
    ${KDIR}/arch/x86/include/uapi
    ${KDIR}/arch/x86/include/generated/uapi
    ${KDIR}/include/uapi
    ${KDIR}/include/generated/uapi
)

add_compile_definitions(
    __KERNEL__
    _LINUX_KERNEL_
    MODULE
    CC_USING_FENTRY
)

add_compile_options(
    -fmacro-prefix-map=./=
    -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs
    -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE
    -Werror=implicit-function-declaration -Werror=implicit-int
    -Werror=return-type -Wno-format-security
    -std=gnu99
    -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none
    -falign-jumps=1 -falign-loops=1
    -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic
    -mno-red-zone -mcmodel=kernel
    -DCONFIG_X86_X32_ABI
    -Wno-sign-compare -fno-asynchronous-unwind-tables
    -mindirect-branch=thunk-extern -mindirect-branch-register
    -mfunction-return=thunk-extern -fno-jump-tables
    -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation
    -Wno-format-overflow -Wno-address-of-packed-member
    -O2
    -fno-allow-store-data-races -Wframe-larger-than=1024
    -fstack-protector-strong -Wimplicit-fallthrough=5
    -Wno-main -Wno-unused-but-set-variable -Wno-unused-const-variable
    -fno-omit-frame-pointer -fno-optimize-sibling-calls -
    fno-stack-clash-protection
    -g
    -pg -mrecord-mcount -mfentry
    -Wdeclaration-after-statement -Wvla -Wno-pointer-sign
    -Wno-stringop-truncation -Wno-zero-length-bounds -Wno-array-bounds
    -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized
    -Wno-alloc-size-larger-than -fno-strict-overflow -fno-stack-check
    -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types
    -Werror=designated-init -Wno-packed-not-aligned
    -Wno-declaration-after-statement -Wframe-larger-than=4096 -ffreestanding
)
#
# ---
#
