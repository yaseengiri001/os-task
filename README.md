# os-task — ST5004CEM Operating Systems and Security

Core operating-system concepts implemented from scratch in **C**, using only the
POSIX standard library. The work is organised into four independent tasks. Each
task is built up from small, focused sub-parts and then combined into a single
integrated program, so every requirement can be read in isolation and also seen
working as part of a whole.

[![Build and run on Linux](https://github.com/yaseengiri001/os-task/actions/workflows/build-and-run.yml/badge.svg)](https://github.com/yaseengiri001/os-task/actions/workflows/build-and-run.yml)

---

## Tasks

| Task | Topic | Status |
|------|-------|--------|
| 1 | Process management & threading — threads, mutexes, semaphores, round-robin scheduling, deadlock prevention | ✅ complete |
| 2 | Memory management simulation — paging, FIFO / LRU / CLOCK / OPT replacement, hit-miss statistics | ✅ complete |
| 3 | File system operations & security — authentication, permissions, authenticated encryption, tamper-evident audit log | ✅ complete |
| 4 | Network programming & IPC — TCP client-server, challenge-response auth, concurrent clients | ✅ complete |

---

## Repository layout

```
task1_process_threading/
├── part1_threads/            3+ concurrent threads
├── part2_synchronization/    mutexes and a counting semaphore
├── part3_round_robin/        round-robin scheduler simulation
├── part4_deadlock/           deadlock demonstration and two preventions
├── task1_combined/           all four integrated, menu-driven
└── outputs/                  captured program output

task2_memory_management/
├── part1_paging/             address translation, configurable page size
├── part2_fifo/               FIFO replacement + Belady's anomaly
├── part3_lru/                LRU replacement + the stack property
├── part4_statistics/         FIFO vs LRU vs CLOCK vs OPT across 3 workloads
├── task2_combined/           all four integrated, menu-driven
└── outputs/

task3_filesystem_security/
├── common/                   SHA-256, HMAC, PBKDF2, ChaCha20 + self-test
├── part1_file_ops/           create / read / write / delete
├── part2_authentication/     PBKDF2 salted hashes, lockout, constant-time compare
├── part3_permissions/        rwx for owner / group / others
├── part4_encryption/         ChaCha20 + HMAC-SHA256 (encrypt-then-MAC)
├── part5_audit_log/          hash-chained, tamper-evident log
├── task3_combined/           interactive secure file manager
└── outputs/

task4_network_ipc/
├── part1_basic_socket/       the socket API, one client at a time
├── part2_concurrent/         thread per client
├── part3_protocol_security/  protocol, challenge-response auth, validation
├── task4_combined/           the complete kvstore client-server application
├── PROTOCOL.md               full protocol specification
└── outputs/

tools/capture_outputs.sh      builds and runs everything, capturing output
.github/workflows/            builds and runs everything on Ubuntu + GCC
```

---

## Building and running

Every part ships with its own `Makefile`:

```bash
cd task1_process_threading/part1_threads
make run        # compile and run
make clean      # remove the binary
```

The integrated programs also have a non-interactive mode, which is what
produces the captured logs:

```bash
task1_process_threading/task1_combined/task1_combined all
task2_memory_management/task2_combined/task2_combined all
task3_filesystem_security/task3_combined/task3_combined demo
cd task4_network_ipc/task4_combined && make demo
```

To build and run **everything** and refresh every captured log:

```bash
tools/capture_outputs.sh
```

---

## Verifying the cryptography

Tasks 3 and 4 rely on a hand-written SHA-256, HMAC-SHA256, PBKDF2 and ChaCha20.
A hash function that is subtly wrong still produces confident-looking output —
authentication would appear to work, because a wrong hash compared against
another wrong hash still matches. The only way to know is to check against
vectors published with the standards:

```bash
cd task3_filesystem_security/common && make test
```

This runs 15 checks drawn from **FIPS 180-4** (SHA-256), **RFC 4231**
(HMAC-SHA256), **RFC 7914** (PBKDF2) and **RFC 8439** (ChaCha20). It runs first
in CI, and a failure stops the build.

---

## Portability and where the output comes from

All code targets **POSIX** and compiles cleanly under `-Wall -Wextra -Werror`
with both `clang` and `gcc`. The GitHub Actions workflow compiles every file
with GCC on Ubuntu, runs the crypto self-test, then executes every program and
uploads the captured logs as build artifacts.

That workflow is deliberately more than a convenience: the output reproduced in
the report is downloaded from it, so the claim that the programs were built and
run on Linux with GCC is verifiable rather than merely asserted. Every captured
file records the kernel and compiler version in its header.

The simulations use a small fixed linear congruential generator rather than
`rand()`, because `rand()` differs between C libraries. Every figure is
therefore byte-for-byte reproducible on any machine that compiles the code.

---

## Notes on scope

The security work is written to demonstrate the mechanisms, and its limits are
documented alongside the code rather than left implied:

- the cryptographic primitives are hand-written for teaching purposes; real
  systems must use a reviewed library such as OpenSSL or libsodium;
- the audit log's chain key lives on the same machine it protects, so a local
  attacker with root could forge a consistent log — real deployments ship
  entries to a separate host;
- the network protocol authenticates but does not encrypt, and would be run
  inside TLS in practice.

Each of these is explained where it matters, in the file it applies to.
