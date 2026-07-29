/*
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 * Part 3 of 4: LRU page replacement
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 2.1(2), second algorithm: "Simulate page replacement algorithms
 *   (at least two: FIFO and LRU)."
 *
 * WHAT LRU FIXES
 *   FIFO (Part 2) evicts the OLDEST page. Age is a bad predictor: a page loaded
 *   first but touched on every reference gets thrown out anyway. Least Recently
 *   Used evicts the page that has gone UNUSED for the longest time instead.
 *
 * WHY THAT IS A BETTER GUESS: LOCALITY OF REFERENCE
 *   Real programs do not touch memory randomly. They spend long stretches
 *   inside one loop and one array - this is called temporal locality: a page
 *   used recently is very likely to be used again soon. LRU is the natural
 *   approximation of the (unimplementable) optimal policy under that
 *   assumption, because it uses the recent past as a prediction of the near
 *   future.
 *
 * HOW IT IS IMPLEMENTED HERE
 *   Every frame carries a `last_used` timestamp - a simple counter that ticks
 *   once per reference. On a HIT we refresh that timestamp; on a FAULT we evict
 *   whichever resident frame has the SMALLEST timestamp.
 *
 *   This costs a scan of the frames on each fault (O(frames)), which is fine
 *   for a simulation. Production kernels cannot afford exact LRU - updating a
 *   timestamp or moving a list node on EVERY memory reference would be far too
 *   slow in hardware - so they approximate it with the CLOCK / second-chance
 *   algorithm using a single reference bit per page. Part 4 implements CLOCK
 *   so the approximation can be compared against true LRU.
 *
 * THE STACK PROPERTY (why LRU cannot suffer Belady's anomaly)
 *   LRU is a "stack algorithm": the set of pages held with N frames is always a
 *   SUBSET of the set held with N+1 frames. Adding a frame can therefore only
 *   ever remove faults, never create them. The sweep at the end of this file
 *   demonstrates that on the very reference string that broke FIFO.
 *
 * BUILD & RUN
 *   make run              # 3 frames (default)
 *   ./lru 4               # same reference string with 4 frames
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_FRAMES 16
#define EMPTY      -1

/* The SAME reference string as Part 2, so the two algorithms can be compared
   fairly. Comparing algorithms on different inputs would be meaningless.    */
static const int reference_string[] = { 1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5 };
static const int REF_LEN = (int)(sizeof(reference_string) / sizeof(reference_string[0]));

static void print_frames(const int *frames, int n)
{
    for (int i = 0; i < n; i++) {
        if (frames[i] == EMPTY) printf("  . ");
        else                    printf(" %2d ", frames[i]);
    }
}

/*
 * Run one LRU simulation.
 *   verbose = 1 -> print the step-by-step table, including each frame's age
 *   verbose = 0 -> silent; just return the fault count (used by the sweep)
 */
static int simulate_lru(int num_frames, int verbose)
{
    int frames[MAX_FRAMES];
    int last_used[MAX_FRAMES];    /* "clock" reading when this frame was last hit */
    int faults = 0, hits = 0;
    int clock = 0;                /* ticks once per reference                 */

    for (int i = 0; i < num_frames; i++) { frames[i] = EMPTY; last_used[i] = 0; }

    if (verbose) {
        printf("Ref | ");
        for (int i = 0; i < num_frames; i++) printf(" F%-2d", i);
        printf(" | Result   Detail\n");
        printf("----+-");
        for (int i = 0; i < num_frames; i++) printf("----");
        printf("-+------------------------------\n");
    }

    for (int i = 0; i < REF_LEN; i++) {
        int page = reference_string[i];
        clock++;

        /* ---- Step 1: look for the page (a HIT) --------------------------- */
        int hit_frame = -1;
        for (int f = 0; f < num_frames; f++) {
            if (frames[f] == page) { hit_frame = f; break; }
        }

        if (hit_frame != -1) {
            /* HIT. Unlike FIFO, LRU MUST do work here: refreshing the
               timestamp is what makes the page "recently used" and saves it
               from being chosen as the next victim. This bookkeeping on every
               hit is exactly what makes true LRU expensive in hardware.      */
            hits++;
            last_used[hit_frame] = clock;
            if (verbose) {
                printf(" %2d | ", page);
                print_frames(frames, num_frames);
                printf(" | HIT      refreshed frame %d\n", hit_frame);
            }
            continue;
        }

        /* ---- Step 2: a FAULT - choose a victim --------------------------- */
        faults++;

        /* Prefer a genuinely free frame if one exists. */
        int victim = -1;
        for (int f = 0; f < num_frames; f++) {
            if (frames[f] == EMPTY) { victim = f; break; }
        }

        int evicted = EMPTY;
        if (victim == -1) {
            /* Memory is full: evict the frame with the OLDEST last_used
               timestamp - that is the least recently used page.             */
            victim = 0;
            for (int f = 1; f < num_frames; f++)
                if (last_used[f] < last_used[victim]) victim = f;
            evicted = frames[victim];
        }

        frames[victim]    = page;
        last_used[victim] = clock;

        if (verbose) {
            printf(" %2d | ", page);
            print_frames(frames, num_frames);
            if (evicted == EMPTY)
                printf(" | FAULT    (free frame %d)\n", victim);
            else
                printf(" | FAULT    evicted page %d (least recently used)\n",
                       evicted);
        }
    }

    if (verbose) {
        printf("\nResults for LRU with %d frames\n", num_frames);
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

    printf("=== LRU (Least Recently Used) page replacement ===\n\n");
    printf("Policy: evict the page that has gone UNUSED for the longest time,\n");
    printf("        on the assumption that recent use predicts future use.\n\n");

    printf("Reference string (%d references):\n  ", REF_LEN);
    for (int i = 0; i < REF_LEN; i++) printf("%d ", reference_string[i]);
    printf("\n\nSimulation with %d frames  ('.' = empty frame)\n\n", num_frames);

    simulate_lru(num_frames, 1);

    /* ---- Stack-property sweep -------------------------------------------
     * The same sweep Part 2 ran on FIFO. Under LRU the fault count must be
     * monotonically non-increasing as frames are added; we verify that
     * explicitly rather than merely asserting it.                            */
    printf("\n\n=== Stack property check (the anomaly FIFO showed) ===\n");
    printf("For LRU, adding a frame must never increase the fault count.\n\n");
    printf("  Frames  Page faults\n");
    printf("  ------  -----------\n");

    int previous = -1, anomaly_seen = 0;
    for (int f = 1; f <= 5; f++) {
        int faults = simulate_lru(f, 0);
        printf("  %-6d  %-11d", f, faults);
        if (previous != -1) {
            if (faults > previous) { printf("  <-- ANOMALY"); anomaly_seen = 1; }
            else if (faults < previous) printf("  (improved)");
            else printf("  (no change)");
        }
        printf("\n");
        previous = faults;
    }

    if (!anomaly_seen) {
        printf("\nNo anomaly, as theory predicts. LRU is a stack algorithm: the\n");
        printf("pages resident with N frames are always a subset of those\n");
        printf("resident with N+1 frames, so extra memory can only ever help.\n");
        printf("On this same reference string FIFO (Part 2) DID show the anomaly.\n");
    }

    return EXIT_SUCCESS;
}
