# QuantumVault

A post-quantum encrypted local filesystem for Linux. You mount a virtual
drive with FUSE; every file written to it is encrypted with CRYSTALS-Kyber
(ML-KEM) before it reaches the disk. Even a stolen drive is useless to an
attacker who waits for quantum computers to break RSA/ECC - that "harvest
now, decrypt later" threat is exactly what this is for.

Modules (one owner each):
- crypto engine - C + liboqs (Kyber key encapsulation, Dilithium signatures)
- virtual filesystem - Rust + FUSE, encrypts on write, decrypts on read
- key management daemon - Rust, generates/stores/wipes key pairs
- CLI - mounts/unmounts the vault, manages identities

Branches:
- main - reviewed, merged work only
- develop - full-project integration testing
- member-N - each member's working branch

Status: week 1 has started - setting up liboqs and the first Kyber demo.
