# Attestation Library

## How to use?

To build the library, use the following commands:

```shell
mkdir build
cd build
cmake ..
```

If build cross-platform target, use:

```shell
cmake .. -DCMAKE_TOOLCHAIN_FILE=../target-linux-<arch>-<abi>.cmake
```

And then use:

```shell
make mbedtls-config
make mbedcrypto
```

to build the backend library. Then use:

```shell
make enclave
```

to build the enclave library.

## Test

The test cases is under the directory `test/`:
- `demo_enclave_attestation.c` : simple attestation demo

### demo-attestation

Build:

```shell
# in build/ directory
make demo_enclave_attestation
```

Run:

```shell
./test/demo_enclave_attestation
```

Expected results:

```asciidoc
install device / enclave identities ...
system booting ...
load enclave ...
start handshake ...
challenge token: 03 00 1d 20 97 a8 3f be 68 8f 38 e5 72 a6 57 1a c0 25 e1 a5 40 52 fd a6 4b 36 88 8f c3 91 21 47 74 a2 22 0b 00 00 00 00 24 00 00 00 00 00 00 00 
report token: 20 e1 5e 13 97 a2 8b 01 3e 17 70 65 da a3 64 e3 ba e7 67 d8 7c 5f 3a ce 74 5a b2 0b 02 71 46 85 16 00 00 00 00 00 00 00 21 00 00 00 00 00 00 00 04 ab 55 3b a3 af 69 a0 49 b6 83 33 98 73 4d ec e5 e7 86 40 b6 60 88 31 71 7d 9d 17 0d 83 4d 5e 3d ea 5c de 9f 41 7b 6a 7d a0 9c 3f 4b fc 40 7d d8 73 70 02 73 37 99 39 ae c5 18 35 d3 1a 61 46 93 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 00 00 00 00 00 00 30 45 02 21 00 a0 88 ff ec 2f bf 7b 0d ad 8f 07 2f 26 6d f8 33 2e aa 00 ff c3 34 be b9 c4 ec 97 d9 6c b1 89 19 02 20 61 05 13 c0 4e 06 54 a8 f2 d1 78 eb f3 2d 31 d3 6e e4 e3 b2 35 a3 a2 50 6a b9 59 f6 cd 2e 48 c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 00 00 00 00 00 00 00 30 45 02 20 6c dd 16 b2 07 88 10 64 d0 3d 0a d8 1f 37 70 8c 35 94 82 98 51 fe 39 88 be 71 72 36 ed 8b d9 84 02 21 00 fc 76 a5 be bc 80 63 0b 15 17 d6 d5 55 13 f7 a0 9c 67 64 e0 13 84 06 84 8f 64 94 ea 6d 89 41 9c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 00 00 00 00 00 00 00 30 45 02 20 06 16 31 11 e5 c0 98 4f 5e 10 f3 99 16 44 83 9e f8 d2 cf c9 78 1f cf be 28 da e2 d4 ae 85 e6 af 02 21 00 c3 1c 5e 1f 99 1e 84 33 07 86 f1 44 6e c6 fd 33 c0 02 1b 42 f0 91 31 cf 15 46 c6 6b d4 74 cb 6b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 00 00 00 00 00 00 00 
peer identity verified!
start message transfer ...
read open channel for 29 bytes: 37 1d c1 56 5d 8e ae fa f5 ce b6 34 1a b1 68 55 31 53 7e 72 3b 43 fb 89 15 bc b8 4c ae 
decrypt: Hello, world!
```

