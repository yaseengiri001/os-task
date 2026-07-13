/*
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 * Part 2 of 4: Synchronization (mutexes and semaphores)
 * -----------------------------------------------------------------------------
 * GOAL
 *   Requirement 1.1(2): "Implement proper synchronization mechanisms
 *   (mutexes, semaphores, or monitors)."
 *
 *   Part 1 deliberately avoided shared data. Here we SHARE one counter between
 *   several threads so you can SEE a race condition, then FIX it two ways:
 *     (A) a mutex             - guarantees the correct total
 *     (B) a counting semaphore - limits how many threads enter a region at once
 *
 * WHY THE RACE HAPPENS (the key idea)
 *   `counter++` looks like one step but the CPU actually does three:
 *        read counter  ->  add 1  ->  write counter
 *   If thread A reads the value, then thread B reads the SAME old value before
 *   A writes back, one of the two increments is lost. Over millions of
 *   increments many are lost, so the UNSYNCHRONIZED total comes out TOO LOW.
 *   A mutex makes those three steps one indivisible "critical section".
 *
 * NOTE
 *   Compiled without optimisation (see Makefile) so the race is visible; an
 *   optimiser could otherwise collapse the loop and hide it.
 *
 * BUILD & RUN
 *   make run
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>  /* sem_open / sem_wait / sem_post (named semaphores)   */
#include <fcntl.h>      /* O_CREAT                                             */
#include <unistd.h>     /* usleep                                             */

#define NUM_THREADS 4
#define ITERATIONS  1000000L   /* increments per thread */

/* ======================= (A) RACE CONDITION + MUTEX ======================= */

static long shared_counter = 0;
static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

/* UNSAFE: increment with no lock -> the race loses updates. */
void *increment_unsafe(void *arg)
{
    (void)arg;
    for (long i = 0; i < ITERATIONS; i++) {
        shared_counter++;                 /* read-modify-write, NOT atomic */
    }
    return NULL;
}

/* SAFE: the mutex makes the increment a single, indivisible critical section. */
void *increment_safe(void *arg)
{
    (void)arg;
    for (long i = 0; i < ITERATIONS; i++) {
        pthread_mutex_lock(&counter_mutex);
        shared_counter++;                 /* only ONE thread in here at a time */
        pthread_mutex_unlock(&counter_mutex);
    }
    return NULL;
}

/* Run one pass: reset counter, launch NUM_THREADS on fn, join, return total. */
static long run_pass(void *(*fn)(void *))
{
    pthread_t t[NUM_THREADS];
    shared_counter = 0;
    for (int i = 0; i < NUM_THREADS; i++) pthread_create(&t[i], NULL, fn, NULL);
    for (int i = 0; i < NUM_THREADS; i++) pthread_join(t[i], NULL);
    return shared_counter;
}

/* ===================== (B) COUNTING SEMAPHORE DEMO ======================== */
/* A counting semaphore with PERMITS permits lets at most PERMITS threads into
 * a region at once - e.g. modelling a printer pool with only 2 printers.     */

#define PERMITS 2
#define SEM_NAME "/os_task_room"

static sem_t *room;                        /* named semaphore (works on macOS) */
static int active = 0;                     /* threads currently 'inside'       */
static int max_active = 0;                 /* peak concurrency observed        */
static pthread_mutex_t active_mutex = PTHREAD_MUTEX_INITIALIZER;

void *use_limited_resource(void *arg)
{
    long id = (long)arg;

    sem_wait(room);                        /* take a permit (blocks if none)   */

    pthread_mutex_lock(&active_mutex);
    active++;
    if (active > max_active) max_active = active;
    printf("  thread %ld entered  (active now = %d)\n", id, active);
    pthread_mutex_unlock(&active_mutex);

    usleep(100000);                        /* pretend to use it for 0.1s       */

    pthread_mutex_lock(&active_mutex);
    printf("  thread %ld leaving  (active now = %d)\n", id, active);
    active--;
    pthread_mutex_unlock(&active_mutex);

    sem_post(room);                        /* return the permit                */
    return NULL;
}

/* =============================== MAIN ==================================== */

int main(void)
{
    long expected = (long)NUM_THREADS * ITERATIONS;

    printf("=== (A) Race condition demo ===\n");
    printf("Each of %d threads increments a shared counter %ld times.\n",
           NUM_THREADS, ITERATIONS);
    printf("Expected final value = %ld\n\n", expected);

    long unsafe = run_pass(increment_unsafe);
    printf("WITHOUT mutex : %-10ld %s\n", unsafe,
           unsafe == expected ? "(no updates lost this run - try again)"
                              : "<-- WRONG: updates were lost to the race");

    long safe = run_pass(increment_safe);
    printf("WITH mutex    : %-10ld %s\n\n", safe,
           safe == expected ? "<-- correct, every increment counted"
                            : "<-- unexpected");

    printf("=== (B) Counting semaphore demo (max %d threads at a time) ===\n",
           PERMITS);
    sem_unlink(SEM_NAME);                   /* clear any stale semaphore first  */
    room = sem_open(SEM_NAME, O_CREAT, 0644, PERMITS);
    if (room == SEM_FAILED) { perror("sem_open"); return EXIT_FAILURE; }

    pthread_t t[6];
    for (long i = 0; i < 6; i++)
        pthread_create(&t[i], NULL, use_limited_resource, (void *)(i + 1));
    for (int i = 0; i < 6; i++)
        pthread_join(t[i], NULL);

    printf("Peak concurrent threads in the region = %d (limit was %d)\n",
           max_active, PERMITS);

    sem_close(room);
    sem_unlink(SEM_NAME);
    return EXIT_SUCCESS;
}
