# QuantumVault - Work Distribution

status snapshot: nov 15 2026. living doc - updated as ownership changes.

## project in one paragraph
post-quantum encrypted virtual drive for linux. a FUSE filesystem where
every file is encrypted with NIST-standardized quantum-safe algorithms
(ML-KEM-768 key delivery, AES-256-GCM bulk encryption, ML-DSA-65
signatures) before it reaches the disk. threat model: harvest-now,
decrypt-later - a stolen drive must stay unreadable even after quantum
computers break RSA/ECC.

## modules and owners

| module | owner | stack | status (nov 15) |
|---|---|---|---|
| crypto engine | rafael (member-1) | C, liboqs, openssl | ahead of plan: liboqs built, ML-KEM-768 roundtrip, hybrid AES-GCM with tamper tests, ML-DSA-65 sign/verify all working and committed |
| virtual filesystem | pending - karthick deciding, deadline nov 15 night | rust + FUSE | not started |
| key management daemon | sumaya (member-3) | rust | not started (exams; research-notes commits until they end) |
| CLI interface | sumaya (member-3) | rust | not started |

team note: one member (ingensumit) left the project nov 12; reported to
infotact with proof. 3 active members cover 4 modules; the filesystem
module reassigns nov 16 if still unclaimed.

## week plan

| week | crypto engine | filesystem | key daemon | CLI |
|---|---|---|---|---|
| 1 (nov 10-16) | liboqs, KEM demo, hybrid demo | owner + env setup | hybrid design note | command spec |
| 2 (nov 17-23) | freeze C header contract, engine API impl | FFI bindings, write-hook encrypt | keypair gen + key store | arg parsing, init/mount stubs |
| 3 (nov 24-30) | dilithium signing of file headers, memory audit | read-hook decrypt | key rotation, mlock + wipe | mount/unmount flow |
| 4 (dec 1-10) | hardening, failure-mode tests | polish + failure handling | swap audit | master password flow |

## repo layout
- main: reviewed merges only (branch-protected: PR + 1 approval)
- develop: integration testing (branch-protected: PR + 1 approval)
- member-N: personal working branches, daily commits

## working rules (infotact handbook)
- daily commits on own branch; docs/research/tests count as progress
- mid review nov 20-27: 10 team commit-days in the prior 14 days
- final review dec 5-10: 20 days of commits, no gaps
- team channel response within 24h; 48h silence gets reported
