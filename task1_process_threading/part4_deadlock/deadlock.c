/*
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 * Part 4 of 4: Deadlock demonstration and prevention
 * -----------------------------------------------------------------------------
 * GOAL
 *   Requirement 1.1(4): "Handle race conditions and demonstrate deadlock
 *   prevention."
 *
 * WHAT A DEADLOCK IS
 *   Two (or more) threads freeze forever, each holding a lock the other needs.
 *   The textbook trigger: two threads take two locks in OPPOSITE order.
 *       Thread 1: lock A ... then wants B
 *       Thread 2: lock B ... then wants A
 *   Thread 1 holds A and waits for B; Thread 2 holds B and waits for A -> stuck.
 *
 * THE FOUR COFFMAN CONDITIONS (all four must hold for deadlock)
 *   1. Mutual exclusion   - a lock is held by only one thread
 *   2. Hold and wait      - a thread holds one lock while waiting for another
 *   3. No preemption      - a lock can't be forcibly taken away
 *   4. Circular wait      - a cycle of threads each waiting on the next
 *   Break ANY ONE of them and deadlock becomes impossible. This file breaks
 *   the CIRCULAR WAIT condition two different ways.
 *
 * OUR EXAMPLE: transferring money between two locked bank accounts.
 *   Thread 1 repeatedly transfers acct0 -> acct1
 *   Thread 2 repeatedly transfers acct1 -> acct0   (the opposite direction!)
 *   Each transfer needs BOTH account locks, so the naive version deadlocks.
 *
 * BUILD & RUN
 *   make run            # runs the two SAFE preventions (both finish)
 *   ./deadlock naive    # OPTIONAL: watch the unsafe version hang (Ctrl-C)
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define N_ACCOUNTS 2
#define TRANSFERS  100000L   /* transfers per thread */

typedef struct {
    long            balance;
    pthread_mutex_t lock;
} Account;

static Account accounts[N_ACCOUNTS];

typedef struct {
    int  from, to;     /* transfer direction for this thread */
    long transfers;
    long retries;      /* backoffs, used by the trylock demo */
    int  mode;         /* 0 = ordered, 1 = trylock, 2 = naive */
} Job;

/* --- PREVENTION 1: LOCK ORDERING -----------------------------------------
 * Always acquire the lower-numbered account lock FIRST, no matter which way
 * the money is moving. Because every thread takes locks in the same global
 * order, no cycle can form -> circular wait is impossible.                  */
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
 * Take the first lock, then TRY the second without blocking. If the second
 * is busy, release the first and start over. A thread never *waits* while
 * holding a lock, so "hold and wait" is broken -> no deadlock.              */
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
        sched_yield();                            /* let the other thread go */
    }
}

/* --- THE UNSAFE VERSION (for demonstration only) -------------------------
 * Locks 'from' then 'to'. With opposite transfers this deadlocks. The
 * usleep widens the timing window so the deadlock happens almost instantly. */
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

static void *worker(void *arg)
{
    Job *j = (Job *)arg;
    for (long i = 0; i < j->transfers; i++) {
        if      (j->mode == 0) transfer_ordered(j->from, j->to, 1);
        else if (j->mode == 1) j->retries += transfer_trylock(j->from, j->to, 1);
        else                   transfer_naive(j->from, j->to, 1);
    }
    return NULL;
}

static void reset_accounts(void)
{
    accounts[0].balance = 1000;
    accounts[1].balance = 1000;
}

static void run_demo(const char *title, int mode)
{
    reset_accounts();
    Job j1 = { 0, 1, TRANSFERS, 0, mode };   /* thread 1: acct0 -> acct1 */
    Job j2 = { 1, 0, TRANSFERS, 0, mode };   /* thread 2: acct1 -> acct0 */
    pthread_t t1, t2;

    printf("%s\n", title);
    pthread_create(&t1, NULL, worker, &j1);
    pthread_create(&t2, NULL, worker, &j2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("  finished - no deadlock.\n");
    printf("  balances: acct0=%ld  acct1=%ld  total=%ld (started at 2000)\n",
           accounts[0].balance, accounts[1].balance,
           accounts[0].balance + accounts[1].balance);
    if (mode == 1)
        printf("  trylock backoffs handled: %ld\n", j1.retries + j2.retries);
    printf("\n");
}

int main(int argc, char **argv)
{
    for (int i = 0; i < N_ACCOUNTS; i++)
        pthread_mutex_init(&accounts[i].lock, NULL);

    if (argc > 1 && strcmp(argv[1], "naive") == 0) {
        printf("WARNING: the NAIVE version locks in opposite order and will\n");
        printf("almost certainly DEADLOCK (hang). Press Ctrl-C to stop.\n\n");
        fflush(stdout);   /* make sure the warning shows before we hang */
        run_demo("[naive] locking from->to ...", 2);
        return 0;   /* usually never reached */
    }

    printf("Deadlock prevention: two threads make OPPOSITE transfers between\n");
    printf("two locked accounts - the classic deadlock trigger.\n\n");

    run_demo("[Prevention 1] Lock ordering (lock lower account id first):", 0);
    run_demo("[Prevention 2] Trylock + backoff (never wait holding a lock):", 1);

    printf("Both preventions kept the books correct AND never deadlocked.\n");
    printf("Try './deadlock naive' to watch the unsafe version hang.\n");

    for (int i = 0; i < N_ACCOUNTS; i++)
        pthread_mutex_destroy(&accounts[i].lock);
    return EXIT_SUCCESS;
}
