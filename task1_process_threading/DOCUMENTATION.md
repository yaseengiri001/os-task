# Task 1 — Process Management and Threading: Design Decisions

> **Working design notes** for the Task 1 report (target 500–750 words). Read
> them, make sure you can explain each decision in your own words, and rephrase
> for the final submission so the writing is genuinely yours.

## Approach and structure

Task 1 was built as four small, independent parts — thread creation,
synchronization, scheduling, and deadlock — before being combined. Each part
lives in its own folder with its own `Makefile` and runs on its own, isolating a
single concept per part and mirroring how the requirements are written.

## Language and portability

Implemented in **C** with **POSIX threads (pthreads)**, because pthreads map
directly onto the OS primitives this module studies. Everything targets a POSIX
system (tested on macOS with `cc`/clang) and compiles with `-Wall -Wextra
-std=c11`.

## Part 1 — Thread creation

Three worker threads are created (the required minimum). Each is given its own
slice of the numbers 1..3000 to sum. Because a pthread start routine takes a
single `void *`, each thread receives a pointer to its own argument struct.
**Key decision:** there is *no shared data* here — each thread writes only its
own `result` field — so no lock is needed. This deliberately keeps "thread
creation" separate from "synchronization." `pthread_join` is used before the
partial sums are combined, which guarantees every worker has finished first.

## Part 2 — Synchronization

The design shows the *problem before the fix*. Four threads each increment one
shared counter a million times. Without protection the final total is wrong,
because `counter++` is really read–modify–write and concurrent threads lose
updates (a race condition). A **`pthread_mutex`** then makes the increment a
single critical section, producing the exact total. A **counting semaphore**
is also demonstrated, capping how many threads may enter a region at once
(like a pool of two printers). A *named* semaphore (`sem_open`) was used
because macOS does not support unnamed `sem_init`. The code is compiled without
`-O` so the race stays observable — an optimiser could otherwise hide it.

## Part 3 — Round-robin scheduler

Scheduling is implemented as a **discrete simulation** (processes modelled as
data) rather than with real threads, because that makes the algorithm and its
metrics explicit and reproducible. A circular ready queue holds the processes;
each runs for `min(quantum, remaining)` and, if unfinished, returns to the back
of the queue. The simulation follows the standard convention that a process
arriving at the same instant another is preempted joins the queue *before* the
preempted one. It outputs a Gantt chart and the standard metrics — completion,
turnaround, and waiting time, plus averages.

## Part 4 — Deadlock

A deadlock is modelled with the classic two-lock example: two threads transfer
money between two locked accounts in opposite directions. This is explained
through the four **Coffman conditions**, and two preventions are provided, each
breaking the cycle a different way: (1) **lock ordering** — always take the
lower-numbered lock first, so no circular wait can form; and (2) **trylock +
backoff** — never block while holding a lock; release and retry instead. An
opt-in "naive" version that genuinely deadlocks is included to demonstrate the
failure, guarded behind a command-line argument so the default run always
terminates.

## The combined program

`task1_combined/` integrates all four parts into the single application the
brief asks for, behind a menu so a reader can jump straight to one requirement.
The one design problem the combined build introduces that the standalone parts
never had is **state**: a standalone `main` runs once and exits, so leftover
globals do not matter, whereas here any demo may be run repeatedly in any order.
Each demo therefore resets its own state on entry — counter zeroed, balances
restored, ready queue emptied — and the account mutexes are initialised exactly
once behind a flag. The unsafe deadlock sits on its own menu entry and is
excluded from "run all", because it never returns by design. A command-line mode
(`./task1_combined all`) runs everything without input, which is how the logs in
`outputs/` were captured.

## Testing and limitations

Every part compiles with no warnings and was executed to confirm behaviour, with
the real logs captured in `outputs/`. The race lost 2,831,689 of 4,000,000
increments (≈71%) in the recorded run; the mutex version was exact. The naive
deadlock was confirmed with a watchdog — still alive after 5 seconds, then
killed. Known limitations: the
scheduler simplifies real systems (no I/O bursts, fixed quantum), and
trylock+backoff could in theory livelock under adversarial timing, which is why
`sched_yield()` is used on each retry.
