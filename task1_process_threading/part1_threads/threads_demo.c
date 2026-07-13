/*
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 * Part 1 of 4: Thread creation and concurrent execution
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 1.1(1): "Create multiple threads to perform concurrent tasks
 *   (minimum 3 threads)."
 *
 *   This program creates 3 worker threads. Each thread is given a different
 *   slice of the numbers 1..3000 and computes the sum of its own slice. The
 *   main thread then waits for all workers to finish (pthread_join) and adds
 *   the partial results together.
 *
 * WHY THERE IS NO DATA RACE HERE (important idea)
 *   Each thread writes ONLY into its own WorkerArg slot (its own `result`
 *   field). No two threads ever touch the same memory, so we do NOT need a
 *   lock yet. In Part 2 we deliberately introduce a *shared* resource so that
 *   a lock (mutex/semaphore) becomes necessary - that shows why
 *   synchronization matters.
 *
 * BUILD & RUN
 *   make            # compiles to ./threads_demo
 *   make run        # compiles and runs
 *   (or manually):  cc -Wall -Wextra -pthread -std=c11 -o threads_demo threads_demo.c
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>   /* printf                         */
#include <stdlib.h>  /* EXIT_SUCCESS / EXIT_FAILURE    */
#include <pthread.h> /* POSIX threads: pthread_*        */

#define NUM_THREADS 3   /* minimum required by the brief */

/*
 * Data handed to each worker thread.
 * A pthread's start function can only take ONE void* argument, so the standard
 * pattern is to pack everything the thread needs into a struct and pass a
 * pointer to it.
 */
typedef struct {
    int  thread_id;   /* 1, 2, 3 ... just for readable log output      */
    long start;       /* first number in this thread's slice           */
    long end;         /* last number in this thread's slice            */
    long result;      /* OUTPUT: this thread writes its partial sum here */
} WorkerArg;

/*
 * worker() is the function that actually runs inside each thread.
 * Signature MUST be `void *name(void *)` because that is what
 * pthread_create expects.
 */
void *worker(void *arg)
{
    WorkerArg *w = (WorkerArg *)arg;   /* cast the void* back to our struct */

    printf("[Thread %d] started  -> summing %ld..%ld\n",
           w->thread_id, w->start, w->end);

    long sum = 0;
    for (long i = w->start; i <= w->end; i++) {
        sum += i;
    }

    w->result = sum;   /* store the answer where main() can read it later */

    printf("[Thread %d] finished -> partial sum = %ld\n",
           w->thread_id, sum);

    return NULL;       /* we return results via the struct, not the return value */
}

int main(void)
{
    pthread_t threads[NUM_THREADS];   /* handles/IDs for each thread   */
    WorkerArg args[NUM_THREADS];      /* one argument struct per thread */

    /* Split 1..3000 into 3 equal slices, one per thread. */
    long ranges[NUM_THREADS][2] = {
        {   1, 1000},
        {1001, 2000},
        {2001, 3000}
    };

    printf("Main: creating %d worker threads...\n", NUM_THREADS);

    /* ---- Create the threads ------------------------------------------------
     * pthread_create(&handle, attributes, function, argument)
     * As soon as this returns, the new thread is (potentially) already running
     * *concurrently* with main(). We do not control the exact order in which
     * the threads print - that is the whole point of concurrency.
     */
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i + 1;
        args[i].start     = ranges[i][0];
        args[i].end       = ranges[i][1];
        args[i].result    = 0;

        int rc = pthread_create(&threads[i], NULL, worker, &args[i]);
        if (rc != 0) {
            fprintf(stderr, "Error: pthread_create failed for thread %d (code %d)\n",
                    i + 1, rc);
            return EXIT_FAILURE;
        }
    }

    /* ---- Wait for the threads and combine results --------------------------
     * pthread_join blocks main() until that specific thread has finished.
     * Joining all of them guarantees every partial sum is ready before we add
     * them up. Without join, main() could reach the total *before* the workers
     * finish - a classic bug.
     */
    long total = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total += args[i].result;
    }

    printf("Main: all threads joined. Total sum 1..3000 = %ld\n", total);
    printf("Check: expected             = %ld\n", (3000L * 3001L) / 2);

    return EXIT_SUCCESS;
}
