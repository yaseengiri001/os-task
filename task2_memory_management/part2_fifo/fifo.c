/*
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 * Part 2 of 4: FIFO page replacement
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 2.1(2), first algorithm: "Simulate page replacement algorithms
 *   (at least two: FIFO and LRU)."
 *
 * THE PROBLEM PART 1 LEFT OPEN
 *   Part 1 could load pages only while a frame was free; once physical memory
 *   filled up it had to give up. Real systems keep running by EVICTING a
 *   resident page to make room. Deciding *which* page to evict is the job of a
 *   page replacement algorithm, and that is what this file adds.
 *
 * HOW FIFO WORKS
 *   First-In-First-Out treats memory as a queue: the page that has been
 *   resident the LONGEST is the one thrown out, regardless of how useful it is.
 *   It is implemented here with a single rotating index ("the FIFO hand"):
 *
 *       victim = frames[hand];  frames[hand] = new_page;  hand = (hand+1) % n;
 *
 *   That one line is FIFO's great strength - it needs no bookkeeping on a hit,
 *   so a page hit costs nothing at all.
 *
 * FIFO'S WEAKNESS
 *   Age is a poor guess at future usefulness. A page loaded early and used on
 *   every single reference is evicted purely for being old. That is exactly
 *   what LRU (Part 3) fixes by tracking RECENCY OF USE instead of AGE.
 *
 * BELADY'S ANOMALY (a genuinely surprising result, shown at the end)
 *   You would expect more memory to never make things worse. For FIFO that is
 *   false: on the reference string used below, going from 3 frames to 4 frames
 *   produces MORE page faults, not fewer. Belady and colleagues discovered this
 *   in 1969. It happens because FIFO is not a "stack algorithm" - the set of
 *   pages held with 3 frames is not guaranteed to be a subset of the set held
 *   with 4. LRU is a stack algorithm and can never show this anomaly, which is
 *   one of the strongest theoretical arguments in LRU's favour.
 *
 * BUILD & RUN
 *   make run              # 3 frames (default)
 *   ./fifo 4              # run the same reference string with 4 frames
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_FRAMES 16
#define EMPTY      -1

/*
 * The classic teaching reference string. It is deliberately the one that
 * exhibits Belady's anomaly under FIFO, so the anomaly demo at the bottom of
 * this file is reproducible rather than a lucky accident.
 */
static const int reference_string[] = { 1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5 };
static const int REF_LEN = (int)(sizeof(reference_string) / sizeof(reference_string[0]));

/*
 * Draw the current frame contents as one row of a table. Producing a row per
 * reference gives the "visualization of memory allocation" the brief asks for:
 * the whole history of physical memory is visible in a single block of output.
 */
static void print_frames(const int *frames, int n)
{
    for (int i = 0; i < n; i++) {
        if (frames[i] == EMPTY) printf("  . ");
        else                    printf(" %2d ", frames[i]);
    }
}

/*
 * Run one FIFO simulation.
 *   verbose = 1 -> print the full step-by-step table
 *   verbose = 0 -> stay silent and just return the fault count (used by the
 *                  Belady's anomaly sweep, which runs many simulations)
 * Returns the total number of page faults.
 */
static int simulate_fifo(int num_frames, int verbose)
{
    int frames[MAX_FRAMES];
    int hand = 0;                 /* the FIFO "hand": next frame to overwrite */
    int faults = 0, hits = 0;

    for (int i = 0; i < num_frames; i++) frames[i] = EMPTY;

    if (verbose) {
        printf("Ref | ");
        for (int i = 0; i < num_frames; i++) printf(" F%-2d", i);
        printf(" | Result   Evicted\n");
        printf("----+-");
        for (int i = 0; i < num_frames; i++) printf("----");
        printf("-+------------------\n");
    }

    for (int i = 0; i < REF_LEN; i++) {
        int page = reference_string[i];

        /* ---- Step 1: is the page already resident? (a page HIT) ---------- */
        int found = 0;
        for (int f = 0; f < num_frames; f++) {
            if (frames[f] == page) { found = 1; break; }
        }

        if (found) {
            /* HIT. Note that FIFO does NOTHING here - it does not promote the
               page or update any timestamp. That is precisely why FIFO is
               cheap, and precisely why it makes poor decisions later.        */
            hits++;
            if (verbose) {
                printf(" %2d | ", page);
                print_frames(frames, num_frames);
                printf(" | HIT\n");
            }
            continue;
        }

        /* ---- Step 2: a page FAULT - the page must be brought in ---------- */
        faults++;
        int evicted = frames[hand];      /* EMPTY on the first pass round     */
        frames[hand] = page;
        hand = (hand + 1) % num_frames;  /* advance the hand, wrapping around */

        if (verbose) {
            printf(" %2d | ", page);
            print_frames(frames, num_frames);
            if (evicted == EMPTY) printf(" | FAULT    (free frame)\n");
            else                  printf(" | FAULT    evicted page %d\n", evicted);
        }
    }

    if (verbose) {
        printf("\nResults for FIFO with %d frames\n", num_frames);
        printf("  References  : %d\n", REF_LEN);
        printf("  Page hits   : %d\n", hits);
        printf("  Page faults : %d\n", faults);
        printf("  Hit ratio   : %.2f%%\n", 100.0 * hits   / REF_LEN);
        printf("  Miss ratio  : %.2f%%\n", 100.0 * faults / REF_LEN);
    }
    return faults;
}

int main(int argc, char **argv)
{
    int num_frames = (argc > 1) ? atoi(argv[1]) : 3;

    if (num_frames < 1 || num_frames > MAX_FRAMES) {
        fprintf(stderr, "Error: frame count must be between 1 and %d.\n", MAX_FRAMES);
        return EXIT_FAILURE;
    }

    printf("=== FIFO page replacement ===\n\n");
    printf("Policy: evict the page that has been in memory the LONGEST,\n");
    printf("        regardless of whether it is still being used.\n\n");

    printf("Reference string (%d references):\n  ", REF_LEN);
    for (int i = 0; i < REF_LEN; i++) printf("%d ", reference_string[i]);
    printf("\n\nSimulation with %d frames  ('.' = empty frame)\n\n", num_frames);

    simulate_fifo(num_frames, 1);

    /* ---- Belady's anomaly sweep -----------------------------------------
     * Run the SAME reference string over an increasing number of frames and
     * print the fault count each time. More memory should mean fewer faults;
     * where it does not, we flag the anomaly.                                */
    printf("\n\n=== Belady's anomaly check ===\n");
    printf("More memory should never cause MORE page faults. Under FIFO it can.\n\n");
    printf("  Frames  Page faults\n");
    printf("  ------  -----------\n");

    int previous = -1, anomaly_seen = 0;
    for (int f = 1; f <= 5; f++) {
        int faults = simulate_fifo(f, 0);
        printf("  %-6d  %-11d", f, faults);
        if (previous != -1 && faults > previous) {
            printf("  <-- ANOMALY: %d frames caused MORE faults than %d",
                   f, f - 1);
            anomaly_seen = 1;
        }
        printf("\n");
        previous = faults;
    }

    if (anomaly_seen) {
        printf("\nBelady's anomaly is confirmed on this reference string.\n");
        printf("FIFO is not a stack algorithm: the pages held with N frames are\n");
        printf("not guaranteed to still be held with N+1 frames, so adding memory\n");
        printf("can change the eviction order for the worse.\n");
        printf("LRU (Part 3) is a stack algorithm and can never do this.\n");
    }

    return EXIT_SUCCESS;
}
