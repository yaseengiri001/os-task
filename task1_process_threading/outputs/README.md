# Task 1 — Captured Output Logs

Deliverable 1.2(3): *"Screenshots or output logs demonstrating successful execution."*

Every `.txt` file here is **real captured output** from running the compiled
binaries on macOS (Darwin 25.5.0) with `cc`/clang, C11, `-Wall -Wextra`. Nothing
in these logs was written by hand. To regenerate any of them, run the command
shown on the first line of the file.

| Log file | What it demonstrates | Requirement |
|---|---|---|
| `part1_threads.txt` | 3 threads each sum a slice of 1..3000; partial sums combine to 4501500, self-checked against Gauss's formula | 1.1(1) |
| `part2_synchronization.txt` | Race condition, then the mutex fix, then the counting semaphore | 1.1(2) |
| `part3_round_robin.txt` | Round-robin schedule with Gantt chart and turnaround/waiting metrics | 1.1(3) |
| `part4_deadlock.txt` | Both deadlock-prevention strategies complete with the books balanced | 1.1(4) |
| `part4_deadlock_naive_hang.txt` | **Proof the deadlock is real** — the unsafe version hangs | 1.1(4) |
| `task1_combined_all.txt` | The integrated program running all four demos back to back | all |
| `task1_combined_menu.txt` | The interactive menu, showing option 1 then quit | all |

## The two results worth pointing at when explaining this task

**1. The race condition is severe, not theoretical.** In
`part2_synchronization.txt`, four threads each increment a shared counter one
million times. The correct total is 4,000,000:

```
WITHOUT mutex : 1168311    <-- WRONG: updates were lost to the race
WITH mutex    : 4000000    <-- correct, every increment counted
```

**2,831,689 increments were lost** — about 71% of all the work. This is what
`counter++` not being atomic actually costs: it is read → add → write, and
threads constantly overwrite each other's results. Note the unsafe number
changes on every run, which is itself the point: a race gives you a *different
wrong answer* each time, which is exactly why these bugs are so hard to find.

**2. The deadlock genuinely deadlocks.** `part4_deadlock_naive_hang.txt` shows
the unsafe version being started, producing no further output, and still being
alive 5 seconds later — at which point it was killed with SIGKILL. Two threads
each holding one account lock and waiting for the other will wait forever; no
amount of patience resolves it. Both prevention strategies in
`part4_deadlock.txt` finish in well under a second on the identical workload.

## Note on the trylock backoff count

`part4_deadlock.txt` reports the number of backoffs the trylock strategy needed
(around 69,000 across 200,000 transfers in the captured run). This number varies
between runs because it depends on thread timing. It is worth understanding as a
trade-off rather than a flaw: lock ordering has no retry cost at all, whereas
trylock+backoff burns CPU spinning — but trylock works even when a global lock
order cannot be established, which is common in real systems.
