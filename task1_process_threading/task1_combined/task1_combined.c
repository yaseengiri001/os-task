/*
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 * COMBINED: all four parts in one menu-driven program
 * -----------------------------------------------------------------------------
 * GOAL
 *   Parts 1-4 each demonstrate one requirement in isolation, which makes them
 *   easy to read and to mark. This program brings all four together into the
 *   single "multi-threaded application" the brief asks for:
 *
 *     Requirement 1.1(1)  Create multiple threads to perform concurrent tasks
 *                         (minimum 3 threads)                     -> demo_threads()
 *     Requirement 1.1(2)  Implement proper synchronization mechanisms
 *                         (mutexes, semaphores, or monitors)      -> demo_sync()
 *     Requirement 1.1(3)  Demonstrate process scheduling by implementing a
 *                         simple round-robin scheduler simulation -> demo_round_robin()
 *     Requirement 1.1(4)  Handle race conditions and demonstrate
 *                         deadlock prevention                     -> demo_deadlock()
 *
 * WHY A MENU RATHER THAN ONE LONG RUN
 *   The four demonstrations are independent and some take a noticeable amount
 *   of time (part 2 does four million increments twice). A menu lets a marker
 *   jump straight to the requirement they are assessing instead of scrolling
 *   through the others, and it keeps each demo's output clearly separated.
 *
 * STATE IS RESET BETWEEN RUNS
 *   Every demo re-initialises its own globals on entry (counters zeroed,
 *   balances reset, queue emptied), so any option can be run any number of
 *   times in any order and still produce correct, repeatable results. This is
 *   the main thing the combined build has to get right that the standalone
 *   parts did not: in a standalone program `main` runs once and exits, so
 *   leftover state was never a concern.
 *
 * BUILD & RUN
 *   make                 # compiles to ./task1_combined
 *   make run             # compiles and runs the interactive menu
 *   ./task1_combined all # runs demos 1-4 back to back, no input needed
 *                        # (this non-interactive mode is what produces the
 *                        #  captured output logs in ../outputs/)
 *   ./task1_combined 3   # runs just demo 3 and exits
 *
 * NOTE: compiled WITHOUT optimisation (-O0, see Makefile) so that the race
 * condition in demo 2 stays visible; an optimiser can hoist the increment out
 * of the loop and hide it.
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>  /* sem_open / sem_wait / sem_post (named semaphores) */
#include <fcntl.h>      /* O_CREAT                                           */
#include <unistd.h>     /* usleep                                            */
#include <sched.h>      /* sched_yield                                       */

/* ===================== DEMO 1: THREAD CREATION ============================ */
/* Requirement 1.1(1). Three worker threads each sum their own slice of
 * 1..3000. There is NO shared data - every thread writes only into its own
 * WorkerArg slot - so no lock is needed here. That is deliberate: it keeps
 * "thread creation" separate from "synchronization", which demo 2 covers. */

#define NUM_WORKERS 3      /* the minimum required by the brief */
#define RANGE_END   3000L

typedef struct {
    int  thread_id;   /* 1, 2, 3 ... only used to label log output            */
    long start;       /* first number in this thread's slice                  */
    long end;         /* last number in this thread's slice                   */
    long result;      /* OUTPUT: this thread writes its partial sum here       */
} WorkerArg;

/* A pthread start routine must have exactly this signature: void *(*)(void *) */
static void *worker(void *arg)
{
    WorkerArg *w = (WorkerArg *)arg;   /* cast the void* back to our struct */

    printf("  [Thread %d] started  -> summing %ld..%ld\n",
           w->thread_id, w->start, w->end);

    long sum = 0;
    for (long i = w->start; i <= w->end; i++) sum += i;

    w->result = sum;                   /* only this thread touches this field */
    printf("  [Thread %d] finished -> partial sum = %ld\n", w->thread_id, sum);
    return NULL;
}

static void demo_threads(void)
{
    pthread_t  tid[NUM_WORKERS];
    WorkerArg  args[NUM_WORKERS];
    long       slice = RANGE_END / NUM_WORKERS;

    printf("\n=== DEMO 1: Thread creation and concurrent execution ===\n");
    printf("Creating %d threads to sum 1..%ld between them.\n\n",
           NUM_WORKERS, RANGE_END);

    /* --- create --- */
    for (int i = 0; i < NUM_WORKERS; i++) {
        args[i].thread_id = i + 1;
        args[i].start     = i * slice + 1;
        /* last thread absorbs any remainder so the whole range is covered */
        args[i].end       = (i == NUM_WORKERS - 1) ? RANGE_END : (i + 1) * slice;
        args[i].result    = 0;

        if (pthread_create(&tid[i], NULL, worker, &args[i]) != 0) {
            perror("pthread_create");
            return;                    /* bail out rather than join garbage */
        }
    }

    /* --- join: blocks until each worker has finished ---
     * We MUST join before reading args[i].result, otherwise we could read a
     * partial sum a thread has not written yet. */
    long total = 0;
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(tid[i], NULL);
        total += args[i].result;
    }

    /* Gauss's formula gives the answer independently, so we can self-check. */
    long expected = RANGE_END * (RANGE_END + 1) / 2;
    printf("\n  Combined total = %ld   (expected %ld) %s\n",
           total, expected, total == expected ? "OK" : "MISMATCH");
}

/* ================ DEMO 2: RACE CONDITION + SYNCHRONIZATION ================ */
/* Requirement 1.1(2) and the "handle race conditions" half of 1.1(4).
 *
 * `counter++` looks like one step but is really three:  read -> add 1 -> write.
 * If thread A reads the value and thread B reads the SAME old value before A
 * writes back, one increment is lost. A mutex makes those three steps a single
 * indivisible critical section. */

#define SYNC_THREADS 4
#define ITERATIONS   1000000L   /* increments per thread */

static long            shared_counter = 0;
static pthread_mutex_t counter_mutex  = PTHREAD_MUTEX_INITIALIZER;

/* UNSAFE: no lock, so concurrent increments are lost. */
static void *increment_unsafe(void *arg)
{
    (void)arg;
    for (long i = 0; i < ITERATIONS; i++) shared_counter++;   /* NOT atomic */
    return NULL;
}

/* SAFE: the mutex serialises the read-modify-write. */
static void *increment_safe(void *arg)
{
    (void)arg;
    for (long i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&counter_mutex);
        shared_counter++;                    /* only ONE thread in here */
        pthread_mutex_unlock(&counter_mutex);
    }
    return NULL;
}

/* Reset the counter, run SYNC_THREADS copies of fn, join them, return total. */
static long run_counter_pass(void *(*fn)(void *))
{
    pthread_t t[SYNC_THREADS];
    shared_counter = 0;                      /* reset: safe to re-run the demo */
    for (int i = 0; i < SYNC_THREADS; i++) pthread_create(&t[i], NULL, fn, NULL);
    for (int i = 0; i < SYNC_THREADS; i++) pthread_join(t[i], NULL);
    return shared_counter;
}

/* --- counting semaphore: at most PERMITS threads inside the region at once,
 * e.g. a printer pool with only two printers. macOS does not implement
 * unnamed sem_init, so we use a NAMED semaphore, which is portable here. --- */
#define PERMITS  2
#define SEM_NAME "/os_task_combined_room"

static sem_t          *room;
static int             active     = 0;   /* threads currently 'inside'  */
static int             max_active = 0;   /* peak concurrency observed   */
static pthread_mutex_t active_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *use_limited_resource(void *arg)
{
    long id = (long)arg;

    sem_wait(room);                      /* take a permit (blocks if none) */

    pthread_mutex_lock(&active_mutex);
    active++;
    if (active > max_active) max_active = active;
    printf("    thread %ld entered  (active now = %d)\n", id, active);
    pthread_mutex_unlock(&active_mutex);

    usleep(100000);                      /* pretend to use the resource 0.1s */

    pthread_mutex_lock(&active_mutex);
    printf("    thread %ld leaving  (active now = %d)\n", id, active);
    active--;
    pthread_mutex_unlock(&active_mutex);

    sem_post(room);                      /* return the permit */
    return NULL;
}

static void demo_sync(void)
{
    long expected = (long)SYNC_THREADS * ITERATIONS;

    printf("\n=== DEMO 2: Race condition, mutex and counting semaphore ===\n");
    printf("(A) %d threads each increment one shared counter %ld times.\n",
           SYNC_THREADS, ITERATIONS);
    printf("    Expected final value = %ld\n\n", expected);

    long unsafe = run_counter_pass(increment_unsafe);
    printf("    WITHOUT mutex : %-10ld %s\n", unsafe,
           unsafe == expected ? "(no updates lost this run - try again)"
                              : "<-- WRONG: updates lost to the race");

    long safe = run_counter_pass(increment_safe);
    printf("    WITH mutex    : %-10ld %s\n", safe,
           safe == expected ? "<-- correct, every increment counted"
                            : "<-- unexpected");

    printf("\n(B) Counting semaphore: at most %d of 6 threads inside at once.\n",
           PERMITS);

    active = 0; max_active = 0;          /* reset so the demo can be re-run */
    sem_unlink(SEM_NAME);                /* clear any stale semaphore first */
    room = sem_open(SEM_NAME, O_CREAT, 0644, PERMITS);
    if (room == SEM_FAILED) { perror("sem_open"); return; }

    pthread_t t[6];
    for (long i = 0; i < 6; i++)
        pthread_create(&t[i], NULL, use_limited_resource, (void *)(i + 1));
    for (int i = 0; i < 6; i++)
        pthread_join(t[i], NULL);

    printf("    Peak concurrent threads in the region = %d (limit was %d) %s\n",
           max_active, PERMITS, max_active <= PERMITS ? "OK" : "LIMIT BREACHED");

    sem_close(room);
    sem_unlink(SEM_NAME);
}

/* =============== DEMO 3: ROUND-ROBIN SCHEDULER SIMULATION ================= */
/* Requirement 1.1(3).
 *
 * Round-robin gives every process a fixed slice of CPU time (the QUANTUM).
 * The process at the front of the ready queue runs for up to one quantum; if
 * it still needs CPU it goes to the BACK of the queue and the next one runs.
 * Fair, no starvation, good response time - which is why time-sharing systems
 * use it.
 *
 * Metrics:  turnaround = completion - arrival
 *           waiting    = turnaround - burst
 *
 * Ordering convention: a process ARRIVING at the same instant another is
 * preempted joins the queue BEFORE the preempted one re-joins. */

#define MAX_PROC 32
#define MAX_SEG  512     /* Gantt segments (one per time slice) */
#define QCAP     64      /* circular ready-queue capacity       */

typedef struct {
    int pid;          /* process id, e.g. 1 -> "P1"               */
    int arrival;      /* time it enters the system                */
    int burst;        /* total CPU time it needs                  */
    int remaining;    /* CPU time still left (counts down)        */
    int completion;   /* filled in when it finishes               */
    int turnaround;
    int waiting;
} Process;

static int q[QCAP], qhead, qtail, qcount;

static void q_reset(void) { qhead = qtail = qcount = 0; }
static void q_push(int i) { q[qtail] = i; qtail = (qtail + 1) % QCAP; qcount++; }
static int  q_pop(void)   { int x = q[qhead]; qhead = (qhead + 1) % QCAP; qcount--; return x; }
static int  q_empty(void) { return qcount == 0; }

static int seg_pid[MAX_SEG], seg_start[MAX_SEG], seg_end[MAX_SEG], seg_count;

static void demo_round_robin(void)
{
    /* Sample workload - edit these rows to test other scenarios. */
    Process p[] = {
        /* pid, arrival, burst */
        { 1, 0, 5, 0,0,0,0 },
        { 2, 1, 3, 0,0,0,0 },
        { 3, 2, 6, 0,0,0,0 },
        { 4, 3, 1, 0,0,0,0 },
    };
    int n       = (int)(sizeof(p) / sizeof(p[0]));
    int quantum = 2;

    q_reset();                                  /* reset: safe to re-run */
    seg_count = 0;
    for (int i = 0; i < n; i++) p[i].remaining = p[i].burst;

    printf("\n=== DEMO 3: Round-robin scheduler simulation (quantum = %d) ===\n\n",
           quantum);

    /* Consider arrivals in order: by arrival time, ties broken by pid.
       Selection sort on a tiny array - clarity over speed. */
    int order[MAX_PROC];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++)
        for (int j = i + 1; j < n; j++)
            if (p[order[j]].arrival <  p[order[i]].arrival ||
               (p[order[j]].arrival == p[order[i]].arrival &&
                p[order[j]].pid     <  p[order[i]].pid))
            { int t = order[i]; order[i] = order[j]; order[j] = t; }

    int added[MAX_PROC] = {0};   /* has this process been queued yet? */
    int completed = 0;
    int now = 0;

    /* Enqueue everything that has arrived by 'now' and is not yet queued. */
    #define ENQUEUE_ARRIVALS()                                   \
        for (int k = 0; k < n; k++) {                            \
            int idx = order[k];                                  \
            if (!added[idx] && p[idx].arrival <= now) {          \
                q_push(idx); added[idx] = 1;                     \
            } else if (p[idx].arrival > now) {                   \
                break; /* order[] is sorted, so we can stop */   \
            }                                                    \
        }

    ENQUEUE_ARRIVALS();

    while (completed < n) {
        if (q_empty()) {
            /* CPU idle: jump forward to the next arrival. */
            int next = -1;
            for (int k = 0; k < n; k++)
                if (!added[order[k]]) { next = p[order[k]].arrival; break; }
            now = next;
            ENQUEUE_ARRIVALS();
            continue;
        }

        int i     = q_pop();
        int start = now;
        int slice = p[i].remaining < quantum ? p[i].remaining : quantum;

        now            += slice;      /* CPU runs process i for 'slice' units */
        p[i].remaining -= slice;

        seg_pid[seg_count]   = p[i].pid;   /* record for the Gantt chart */
        seg_start[seg_count] = start;
        seg_end[seg_count]   = now;
        seg_count++;

        /* new arrivals enter BEFORE the preempted process re-joins */
        ENQUEUE_ARRIVALS();

        if (p[i].remaining > 0) {
            q_push(i);                /* not done -> back of the queue */
        } else {
            p[i].completion = now;    /* done -> record its metrics    */
            p[i].turnaround = p[i].completion - p[i].arrival;
            p[i].waiting    = p[i].turnaround - p[i].burst;
            completed++;
        }
    }
    #undef ENQUEUE_ARRIVALS

    /* ---- Gantt chart (merge consecutive slices belonging to the same pid) -- */
    printf("Gantt chart:\n ");
    for (int s = 0; s < seg_count; ) {
        int e = s;
        while (e + 1 < seg_count && seg_pid[e + 1] == seg_pid[s]) e++;
        printf("| P%d ", seg_pid[s]);
        s = e + 1;
    }
    printf("|\n ");
    for (int s = 0; s < seg_count; ) {
        int e = s;
        while (e + 1 < seg_count && seg_pid[e + 1] == seg_pid[s]) e++;
        printf("%-5d", seg_start[s]);
        s = e + 1;
    }
    printf("%d\n\n", seg_end[seg_count - 1]);

    /* ------------------------------ results table -------------------------- */
    printf("PID  Arrival  Burst  Completion  Turnaround  Waiting\n");
    printf("---  -------  -----  ----------  ----------  -------\n");
    double sum_tat = 0, sum_wt = 0;
    for (int i = 0; i < n; i++) {
        printf("P%-3d %6d  %5d  %9d  %10d  %7d\n",
               p[i].pid, p[i].arrival, p[i].burst,
               p[i].completion, p[i].turnaround, p[i].waiting);
        sum_tat += p[i].turnaround;
        sum_wt  += p[i].waiting;
    }
    printf("\nAverage turnaround time = %.2f\n", sum_tat / n);
    printf("Average waiting time    = %.2f\n", sum_wt  / n);
}

/* ============ DEMO 4: DEADLOCK DEMONSTRATION AND PREVENTION =============== */
/* Requirement 1.1(4).
 *
 * Two threads transfer money between two locked bank accounts in OPPOSITE
 * directions. Each transfer needs BOTH locks, so the naive version deadlocks:
 *     Thread 1 holds acct0, wants acct1
 *     Thread 2 holds acct1, wants acct0    -> stuck forever
 *
 * THE FOUR COFFMAN CONDITIONS (all four must hold for deadlock):
 *   1. Mutual exclusion  - a lock is held by only one thread
 *   2. Hold and wait     - a thread holds one lock while waiting for another
 *   3. No preemption     - a lock cannot be forcibly taken away
 *   4. Circular wait     - a cycle of threads each waiting on the next
 * Break any ONE and deadlock is impossible. We break #4 and #2 below. */

#define N_ACCOUNTS 2
#define TRANSFERS  100000L   /* transfers per thread */

typedef struct {
    long            balance;
    pthread_mutex_t lock;
} Account;

static Account accounts[N_ACCOUNTS];
static int     accounts_ready = 0;   /* so we only pthread_mutex_init once */

typedef struct {
    int  from, to;     /* transfer direction for this thread     */
    long transfers;
    long retries;      /* backoffs, used by the trylock demo     */
    int  mode;         /* 0 = ordered, 1 = trylock, 2 = naive    */
} Job;

/* --- PREVENTION 1: LOCK ORDERING -----------------------------------------
 * Always take the LOWER-numbered account lock first, whichever way the money
 * is moving. Every thread takes locks in the same global order, so no cycle
 * can form -> circular wait (condition 4) is impossible. */
static void transfer_ordered(int from, int to, long amt)
{
    int lo = from < to ? from : to;
    int hi = from < to ? to : from;

    pthread_mutex_lock(&accounts[lo].lock);
    pthread_mutex_lock(&accounts[hi].lock);

    accounts[from].balance -= amt;
    accounts[to].balance   += amt;

    pthread_mutex_unlock(&accounts[hi].lock);
    pthread_mutex_unlock(&accounts[lo].lock);
}

/* --- PREVENTION 2: TRYLOCK + BACKOFF -------------------------------------
 * Take the first lock, then TRY the second without blocking. If it is busy,
 * release the first and start over. A thread never *waits* while holding a
 * lock, so hold-and-wait (condition 2) is broken -> no deadlock. */
static long transfer_trylock(int from, int to, long amt)
{
    long retries = 0;
    for (;;) {
        pthread_mutex_lock(&accounts[from].lock);
        if (pthread_mutex_trylock(&accounts[to].lock) == 0) {   /* got both */
            accounts[from].balance -= amt;
            accounts[to].balance   += amt;
            pthread_mutex_unlock(&accounts[to].lock);
            pthread_mutex_unlock(&accounts[from].lock);
            return retries;
        }
        pthread_mutex_unlock(&accounts[from].lock);   /* back off and retry */
        retries++;
        sched_yield();                             /* let the other thread go */
    }
}

/* --- THE UNSAFE VERSION (demonstration only) ------------------------------
 * Locks 'from' then 'to'. With opposite transfers this deadlocks. The usleep
 * widens the timing window so it hangs almost immediately. */
static void transfer_naive(int from, int to, long amt)
{
    pthread_mutex_lock(&accounts[from].lock);
    usleep(1);
    pthread_mutex_lock(&accounts[to].lock);

    accounts[from].balance -= amt;
    accounts[to].balance   += amt;

    pthread_mutex_unlock(&accounts[to].lock);
    pthread_mutex_unlock(&accounts[from].lock);
}

static void *bank_worker(void *arg)
{
    Job *j = (Job *)arg;
    for (long i = 0; i < j->transfers; i++) {
        if      (j->mode == 0) transfer_ordered(j->from, j->to, 1);
        else if (j->mode == 1) j->retries += transfer_trylock(j->from, j->to, 1);
        else                   transfer_naive(j->from, j->to, 1);
    }
    return NULL;
}

static void run_bank_demo(const char *title, int mode)
{
    accounts[0].balance = 1000;          /* reset: safe to re-run */
    accounts[1].balance = 1000;

    Job j1 = { 0, 1, TRANSFERS, 0, mode };   /* thread 1: acct0 -> acct1 */
    Job j2 = { 1, 0, TRANSFERS, 0, mode };   /* thread 2: acct1 -> acct0 */
    pthread_t t1, t2;

    printf("  %s\n", title);
    pthread_create(&t1, NULL, bank_worker, &j1);
    pthread_create(&t2, NULL, bank_worker, &j2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("    finished - no deadlock.\n");
    printf("    balances: acct0=%ld  acct1=%ld  total=%ld (started at 2000)\n",
           accounts[0].balance, accounts[1].balance,
           accounts[0].balance + accounts[1].balance);
    if (mode == 1)
        printf("    trylock backoffs handled: %ld\n", j1.retries + j2.retries);
    printf("\n");
}

static void demo_deadlock(void)
{
    if (!accounts_ready) {               /* initialise the locks exactly once */
        for (int i = 0; i < N_ACCOUNTS; i++)
            pthread_mutex_init(&accounts[i].lock, NULL);
        accounts_ready = 1;
    }

    printf("\n=== DEMO 4: Deadlock demonstration and prevention ===\n");
    printf("Two threads make OPPOSITE transfers between two locked accounts -\n");
    printf("the classic deadlock trigger.\n\n");

    run_bank_demo("[Prevention 1] Lock ordering (lock lower account id first):", 0);
    run_bank_demo("[Prevention 2] Trylock + backoff (never wait holding a lock):", 1);

    printf("  Both preventions kept the books correct AND never deadlocked.\n");
    printf("  Menu option 5 runs the UNSAFE version, which hangs on purpose.\n");
}

/* The unsafe version is behind its own menu entry (and never runs in "all"
 * mode) because it is expected to hang forever - that is the whole point. */
static void demo_deadlock_naive(void)
{
    if (!accounts_ready) {
        for (int i = 0; i < N_ACCOUNTS; i++)
            pthread_mutex_init(&accounts[i].lock, NULL);
        accounts_ready = 1;
    }

    printf("\n=== DEMO 5: The UNSAFE version (expected to deadlock) ===\n");
    printf("WARNING: this locks in opposite order and will almost certainly\n");
    printf("HANG. That is the demonstration. Press Ctrl-C to stop it.\n\n");
    fflush(stdout);          /* flush before we hang, or the warning is lost */

    run_bank_demo("[naive] locking from->to with no ordering rule ...", 2);
    printf("  (If you see this line, the race window happened to be missed -\n");
    printf("   run it again and it will hang.)\n");
}

/* ================================ MENU =================================== */

static void print_menu(void)
{
    printf("\n");
    printf("=============================================================\n");
    printf(" ST5004CEM Task 1 - Process Management and Threading\n");
    printf("=============================================================\n");
    printf("  1. Thread creation and concurrent execution   [req 1.1(1)]\n");
    printf("  2. Race condition, mutex and semaphore        [req 1.1(2)]\n");
    printf("  3. Round-robin scheduler simulation           [req 1.1(3)]\n");
    printf("  4. Deadlock prevention (two strategies)       [req 1.1(4)]\n");
    printf("  5. Deadlock demonstration - WILL HANG on purpose\n");
    printf("  6. Run demos 1-4 back to back\n");
    printf("  0. Quit\n");
    printf("-------------------------------------------------------------\n");
    printf("Choice: ");
    fflush(stdout);          /* prompt has no newline, so flush it explicitly */
}

/* Run demos 1-4 in order. Demo 5 is excluded on purpose - it never returns. */
static void run_all(void)
{
    demo_threads();
    demo_sync();
    demo_round_robin();
    demo_deadlock();
    printf("\nAll four demonstrations completed successfully.\n");
}

/* Dispatch a single choice. Returns 0 when the user asked to quit. */
static int dispatch(int choice)
{
    switch (choice) {
        case 1: demo_threads();        break;
        case 2: demo_sync();           break;
        case 3: demo_round_robin();    break;
        case 4: demo_deadlock();       break;
        case 5: demo_deadlock_naive(); break;
        case 6: run_all();             break;
        case 0: printf("Goodbye.\n");  return 0;
        default: printf("Invalid choice - please enter 0-6.\n"); break;
    }
    return 1;
}

int main(int argc, char **argv)
{
    /* ---- non-interactive mode: ./task1_combined all   or   ./task1_combined 3
     * This exists so the run logs in ../outputs/ can be captured with a plain
     * shell redirect, with no keyboard input involved. */
    if (argc > 1) {
        if (strcmp(argv[1], "all") == 0) { run_all(); return EXIT_SUCCESS; }

        char *end;
        long choice = strtol(argv[1], &end, 10);
        if (*end != '\0' || choice < 0 || choice > 6) {
            fprintf(stderr, "Usage: %s [all | 0-6]\n", argv[0]);
            return EXIT_FAILURE;
        }
        dispatch((int)choice);
        return EXIT_SUCCESS;
    }

    /* ---- interactive menu ---- */
    for (;;) {
        print_menu();

        char line[64];
        if (fgets(line, sizeof line, stdin) == NULL) {
            /* EOF (e.g. piped input ran out, or Ctrl-D) - exit cleanly */
            printf("\nInput closed - exiting.\n");
            break;
        }

        char *end;
        long choice = strtol(line, &end, 10);
        /* strtol leaves 'end' at the first non-digit; anything other than the
           trailing newline/spaces means the user typed something that is not
           a plain number. */
        while (*end == ' ' || *end == '\t') end++;
        if (end == line || (*end != '\n' && *end != '\0')) {
            printf("Invalid input - please enter a number 0-6.\n");
            continue;
        }

        if (!dispatch((int)choice)) break;
    }

    return EXIT_SUCCESS;
}
