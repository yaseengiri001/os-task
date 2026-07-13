# os-task

Operating Systems core concepts implemented in **C**. The project is organised
into four independent tasks, each in its own folder. Every task is first built
up from small, focused sub-parts and then combined into a single integrated
program.

## Tasks

| Task | Topic | Status |
|------|-------|--------|
| 1 | Process management & threading (threads, synchronization, round-robin scheduling, deadlock prevention) | 🚧 in progress |
| 2 | Memory management simulation (paging, FIFO & LRU page replacement, hit/miss ratios) | ⬜ planned |
| 3 | File system operations & security (auth, permissions, encryption, audit log) | ⬜ planned |
| 4 | Network programming & IPC (client–server sockets, concurrent clients) | ⬜ planned |

## Repository layout

```
task1_process_threading/
├── part1_threads/          # 3+ concurrent threads
├── part2_synchronization/  # mutexes / semaphores
├── part3_round_robin/      # round-robin scheduler simulation
├── part4_deadlock/         # deadlock prevention
└── task1_combined/         # all four integrated
```

## Building & running

Each part ships with its own `Makefile`.

```bash
cd task1_process_threading/part1_threads
make run        # compiles and runs
make clean      # removes the compiled binary
```

All C code targets a POSIX system (tested on macOS with `cc`/clang) and uses
the standard `pthread` library for threading.
