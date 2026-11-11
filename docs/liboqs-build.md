# liboqs build notes

built on kali linux, nov 11 2026.

## source
- repo: https://github.com/open-quantum-safe/liboqs
- commit f47aaf55391d280c4e9491a5f624d0c7ec89618e (shallow clone, branch main)

## build commands used
- cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_TESTS=OFF -DOQS_ENABLE_KEM_CLASSICAL=OFF
- ninja -C build
- result: 3990/3990 targets compiled, no errors (one harmless .note.GNU-stack assembler warning)

## artifacts
- ~/deps/liboqs/build/lib/liboqs.a - 61,892,450 bytes (static library)
- ~/deps/liboqs/build/lib/liboqs-internal.a - 515,208 bytes
- note: headers are generated into build/include/oqs/ (kem.h lives there, not in include/)

## algorithms enabled in this build
ML-KEM-512, ML-KEM-768, ML-KEM-1024 (verified with build/tests/dump_alg_info)

## next step
first demo: ML-KEM-768 keypair + encaps/decaps through build/include/oqs/kem.h
API: OQS_KEM_keypair (line 303), OQS_KEM_encaps (line 346), OQS_KEM_decaps (line 367)
