/*
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 * COMBINED: all four parts in one menu-driven program
 * -----------------------------------------------------------------------------
 * GOAL
 *   Parts 1-4 each demonstrate one requirement in isolation, which makes them
 *   easy to read and to mark. This program brings all four together into the
 *   single "memory management simulator" the brief asks for:
 *
 *     Requirement 2.1(1)  Implement a paging system with configurable
 *                         page size                              -> demo_paging()
 *     Requirement 2.1(2)  Simulate page replacement algorithms
 *                         (at least two: FIFO and LRU)           -> demo_fifo()
 *                                                                   demo_lru()
 *     Requirement 2.1(3)  Track page faults and calculate
 *                         hit/miss ratios                        -> demo_statistics()
 *     Requirement 2.1(4)  Provide visualization or detailed
 *                         logging of memory allocation           -> all of them
 *
 * WHY A MENU RATHER THAN ONE LONG RUN
 *   The comparison in demo 4 runs four algorithms over three workloads and five
 *   frame counts, so its output is long. A menu lets a marker jump straight to
 *   the requirement being assessed instead of scrolling past the others.
 *
 * STATE IS RESET BETWEEN RUNS
 *   Every demo re-initialises its own arrays on entry (page table cleared,
 *   frames emptied, counters zeroed), so any option can be run any number of
 *   times in any order and still produce identical, repeatable results. This is
 *   the one thing the combined build has to get right that the standalone parts
 *   did not: a standalone `main` runs once and exits, so leftover globals were
 *   never a concern there.
 *
 * DETERMINISM
 *   The synthetic workloads use a small fixed linear congruential generator
 *   rather than rand(), because rand() differs between C libraries. Every
 *   number this program prints is therefore reproducible on any machine that
 *   compiles it, which is what makes the figures in the report verifiable.
 *
 * BUILD & RUN
 *   make                  # compiles to ./task2_combined
 *   make run              # compiles and runs the interactive menu
 *   ./task2_combined all  # runs demos 1-4 back to back, no input needed
 *                         # (this non-interactive mode produces the captured
 *                         #  output logs in ../outputs/)
 *   ./task2_combined 2    # runs just demo 2 and exits
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FRAMES  16
#define MAX_PAGES   1024
#define MAX_REFS    512
#define EMPTY       -1

/* ===================== DEMO 1: PAGING WITH A CONFIGURABLE PAGE SIZE ========
 * Requirement 2.1(1). Turns a virtual address into a physical one using a page
 * table, exactly as a memory management unit (MMU) does.
 *
 *     virtual address = | page number | offset |
 *     page   = addr >> offset_bits
 *     offset = addr &  (page_size - 1)
 *
 * Because the page size is a power of two the split is a shift and a mask, not
 * a division - which is why hardware can do it in a single cycle.
 * ========================================================================== */

#define VIRTUAL_MEM_SIZE  4096
#define PHYSICAL_MEM_SIZE 1024

typedef struct {
    int valid;      /* 1 = page currently loaded in a frame */
    int frame;      /* which frame holds it                 */
} PageTableEntry;

static PageTableEntry pg_table[MAX_PAGES];
static int  pg_frame_owner[MAX_FRAMES];   /* page in each frame, or EMPTY */
static int  pg_page_size, pg_offset_bits, pg_pages, pg_frames;

/* log2 of a power of two, or -1 if n is not a power of two. */
static int log2_exact(int n)
{
    int bits = 0;
    if (n <= 0) return -1;
    while ((n & 1) == 0) { n >>= 1; bits++; }
    return (n == 1) ? bits : -1;
}

static void pg_print_memory(void)
{
    printf("    memory: [");
    for (int f = 0; f < pg_frames; f++) {
        if (pg_frame_owner[f] == EMPTY) printf(" -- ");
        else                            printf(" p%-2d", pg_frame_owner[f]);
    }
    printf(" ]\n");
}

static void demo_paging(int page_size)
{
    /* ---- reset all state so the demo is repeatable ---- */
    pg_page_size   = page_size;
    pg_offset_bits = log2_exact(page_size);
    if (pg_offset_bits < 0 || page_size > PHYSICAL_MEM_SIZE) {
        printf("Invalid page size %d - it must be a power of two, at most %d.\n",
               page_size, PHYSICAL_MEM_SIZE);
        return;
    }
    pg_pages  = VIRTUAL_MEM_SIZE  / pg_page_size;
    pg_frames = PHYSICAL_MEM_SIZE / pg_page_size;
    for (int p = 0; p < pg_pages;  p++) pg_table[p].valid = 0;
    for (int f = 0; f < pg_frames; f++) pg_frame_owner[f] = EMPTY;

    printf("\n=== DEMO 1: Paging with a configurable page size ===\n");
    printf("Requirement 2.1(1)\n\n");
    printf("  Page size       : %d bytes (offset = low %d bits)\n",
           pg_page_size, pg_offset_bits);
    printf("  Virtual memory  : %d bytes = %d pages\n", VIRTUAL_MEM_SIZE, pg_pages);
    printf("  Physical memory : %d bytes = %d frames\n\n", PHYSICAL_MEM_SIZE, pg_frames);
    printf("  Translation: page = addr >> %d, offset = addr & 0x%X\n\n",
           pg_offset_bits, pg_page_size - 1);

    int stream[] = { 0, 100, 260, 1000, 100, 2500, 5000, 3000, 3500, 4000, 300 };
    int n = (int)(sizeof(stream) / sizeof(stream[0]));
    int accesses = 0, hits = 0, faults = 0;

    for (int i = 0; i < n; i++) {
        int va = stream[i];
        accesses++;

        if (va < 0 || va >= VIRTUAL_MEM_SIZE) {
            printf("  addr %-5d -> INVALID (outside 0..%d)\n",
                   va, VIRTUAL_MEM_SIZE - 1);
            continue;
        }

        int page   = va >> pg_offset_bits;
        int offset = va & (pg_page_size - 1);

        if (pg_table[page].valid) {                       /* page HIT */
            hits++;
            int phys = (pg_table[page].frame << pg_offset_bits) | offset;
            printf("  addr %-5d -> page %-3d offset %-4d | HIT   frame %-3d -> phys %-5d\n",
                   va, page, offset, pg_table[page].frame, phys);
            continue;
        }

        faults++;                                          /* page FAULT */
        int frame = EMPTY;
        for (int f = 0; f < pg_frames; f++)
            if (pg_frame_owner[f] == EMPTY) { frame = f; break; }

        if (frame == EMPTY) {
            printf("  addr %-5d -> page %-3d offset %-4d | FAULT  no free frame "
                   "(this is what demos 2 and 3 solve)\n", va, page, offset);
            continue;
        }

        pg_table[page].valid = 1;
        pg_table[page].frame = frame;
        pg_frame_owner[frame] = page;
        int phys = (frame << pg_offset_bits) | offset;
        printf("  addr %-5d -> page %-3d offset %-4d | FAULT  loaded into frame %-3d "
               "-> phys %-5d\n", va, page, offset, frame, phys);
        pg_print_memory();
    }

    printf("\n  Accesses %d | hits %d | faults %d\n", accesses, hits, faults);
    printf("  Trade-off: %d page-table entries, worst-case %d bytes wasted in a\n",
           pg_pages, pg_page_size - 1);
    printf("  process's last page. Smaller pages waste less but need a bigger table.\n");
}

/* ===================== SHARED SIMULATION MACHINERY ========================
 * Demos 2, 3 and 4 all replay a reference string against a set of frames, so
 * the helpers they share live here rather than being written three times.
 * ========================================================================== */

typedef struct {
    int    faults;
    int    hits;
    double hit_ratio;
    double miss_ratio;
} Stats;

static const int classic_string[] = { 1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5 };
static const int CLASSIC_LEN =
    (int)(sizeof(classic_string) / sizeof(classic_string[0]));

static int find_page(const int *frames, int n, int page)
{
    for (int f = 0; f < n; f++) if (frames[f] == page) return f;
    return -1;
}

static int find_free(const int *frames, int n)
{
    for (int f = 0; f < n; f++) if (frames[f] == EMPTY) return f;
    return -1;
}

static Stats finish(int faults, int hits, int total)
{
    Stats s;
    s.faults     = faults;
    s.hits       = hits;
    s.hit_ratio  = 100.0 * hits   / total;
    s.miss_ratio = 100.0 * faults / total;
    return s;
}

static void print_frames(const int *frames, int n)
{
    for (int i = 0; i < n; i++) {
        if (frames[i] == EMPTY) printf("  . ");
        else                    printf(" %2d ", frames[i]);
    }
}

/* ---- FIFO: rotating hand; a hit costs nothing --------------------------- */
static Stats run_fifo(const int *refs, int len, int nframes, int verbose)
{
    int frames[MAX_FRAMES];
    int hand = 0, faults = 0, hits = 0;
    for (int i = 0; i < nframes; i++) frames[i] = EMPTY;

    for (int i = 0; i < len; i++) {
        if (find_page(frames, nframes, refs[i]) != -1) {
            hits++;
            if (verbose) {
                printf(" %2d | ", refs[i]); print_frames(frames, nframes);
                printf(" | HIT\n");
            }
            continue;
        }
        faults++;
        int evicted = frames[hand];
        frames[hand] = refs[i];
        hand = (hand + 1) % nframes;
        if (verbose) {
            printf(" %2d | ", refs[i]); print_frames(frames, nframes);
            if (evicted == EMPTY) printf(" | FAULT    (free frame)\n");
            else                  printf(" | FAULT    evicted page %d\n", evicted);
        }
    }
    return finish(faults, hits, len);
}

/* ---- LRU: evict the oldest last_used timestamp -------------------------- */
static Stats run_lru(const int *refs, int len, int nframes, int verbose)
{
    int frames[MAX_FRAMES], last_used[MAX_FRAMES];
    int faults = 0, hits = 0, clock = 0;
    for (int i = 0; i < nframes; i++) { frames[i] = EMPTY; last_used[i] = 0; }

    for (int i = 0; i < len; i++) {
        clock++;
        int f = find_page(frames, nframes, refs[i]);
        if (f != -1) {
            /* A hit MUST refresh the timestamp - that is what protects the
               page from eviction, and what makes true LRU costly in hardware. */
            hits++; last_used[f] = clock;
            if (verbose) {
                printf(" %2d | ", refs[i]); print_frames(frames, nframes);
                printf(" | HIT      refreshed frame %d\n", f);
            }
            continue;
        }
        faults++;
        int victim = find_free(frames, nframes), evicted = EMPTY;
        if (victim == -1) {
            victim = 0;
            for (int k = 1; k < nframes; k++)
                if (last_used[k] < last_used[victim]) victim = k;
            evicted = frames[victim];
        }
        frames[victim] = refs[i];
        last_used[victim] = clock;
        if (verbose) {
            printf(" %2d | ", refs[i]); print_frames(frames, nframes);
            if (evicted == EMPTY) printf(" | FAULT    (free frame %d)\n", victim);
            else printf(" | FAULT    evicted page %d (least recently used)\n", evicted);
        }
    }
    return finish(faults, hits, len);
}

/* ---- OPT: evict the page whose next use is furthest away ----------------
 * Needs the future, so no real OS can implement it. It is the lower bound
 * that makes "LRU beat FIFO" a meaningful statement.                        */
static Stats run_opt(const int *refs, int len, int nframes)
{
    int frames[MAX_FRAMES];
    int faults = 0, hits = 0;
    for (int i = 0; i < nframes; i++) frames[i] = EMPTY;

    for (int i = 0; i < len; i++) {
        if (find_page(frames, nframes, refs[i]) != -1) { hits++; continue; }
        faults++;
        int victim = find_free(frames, nframes);
        if (victim == -1) {
            int furthest = -1;
            victim = 0;
            for (int f = 0; f < nframes; f++) {
                int next_use = len;                     /* len = never again */
                for (int j = i + 1; j < len; j++)
                    if (refs[j] == frames[f]) { next_use = j; break; }
                if (next_use > furthest) { furthest = next_use; victim = f; }
            }
        }
        frames[victim] = refs[i];
    }
    return finish(faults, hits, len);
}

/* ---- CLOCK (second chance): what real kernels actually use --------------
 * One reference bit per frame. A hit just sets the bit (cheap). On a fault the
 * hand sweeps, clearing set bits (granting second chances) until it meets a
 * clear bit, which it evicts.                                               */
static Stats run_clock(const int *refs, int len, int nframes)
{
    int frames[MAX_FRAMES], ref_bit[MAX_FRAMES];
    int hand = 0, faults = 0, hits = 0;
    for (int i = 0; i < nframes; i++) { frames[i] = EMPTY; ref_bit[i] = 0; }

    for (int i = 0; i < len; i++) {
        int f = find_page(frames, nframes, refs[i]);
        if (f != -1) { hits++; ref_bit[f] = 1; continue; }
        faults++;
        int victim = find_free(frames, nframes);
        if (victim == -1) {
            for (;;) {
                if (ref_bit[hand] == 0) { victim = hand; break; }
                ref_bit[hand] = 0;
                hand = (hand + 1) % nframes;
            }
        }
        frames[victim]  = refs[i];
        ref_bit[victim] = 1;
        hand = (victim + 1) % nframes;
    }
    return finish(faults, hits, len);
}

/* ===================== DEMO 2: FIFO ======================================= */

static void demo_fifo(int nframes)
{
    printf("\n=== DEMO 2: FIFO page replacement ===\n");
    printf("Requirement 2.1(2), first algorithm\n\n");
    printf("Policy: evict the page resident LONGEST, however useful it still is.\n\n");
    printf("Reference string: ");
    for (int i = 0; i < CLASSIC_LEN; i++) printf("%d ", classic_string[i]);
    printf("\n\nSimulation with %d frames  ('.' = empty)\n\n", nframes);

    printf("Ref | ");
    for (int i = 0; i < nframes; i++) printf(" F%-2d", i);
    printf(" | Result   Evicted\n----+-");
    for (int i = 0; i < nframes; i++) printf("----");
    printf("-+------------------\n");

    Stats s = run_fifo(classic_string, CLASSIC_LEN, nframes, 1);

    printf("\n  Page hits %d | page faults %d\n", s.hits, s.faults);
    printf("  Hit ratio %.2f%% | miss ratio %.2f%%\n", s.hit_ratio, s.miss_ratio);

    /* Belady's anomaly: more memory producing MORE faults. */
    printf("\n  Belady's anomaly check (more frames should never be worse):\n");
    int previous = -1, anomaly = 0;
    for (int f = 1; f <= 5; f++) {
        int faults = run_fifo(classic_string, CLASSIC_LEN, f, 0).faults;
        printf("    %d frame(s): %2d faults", f, faults);
        if (previous != -1 && faults > previous) {
            printf("   <-- ANOMALY (worse than %d frames)", f - 1);
            anomaly = 1;
        }
        printf("\n");
        previous = faults;
    }
    if (anomaly)
        printf("  Confirmed. FIFO is not a stack algorithm, so extra memory can\n"
               "  change the eviction order for the worse. LRU cannot do this.\n");
}

/* ===================== DEMO 3: LRU ======================================== */

static void demo_lru(int nframes)
{
    printf("\n=== DEMO 3: LRU page replacement ===\n");
    printf("Requirement 2.1(2), second algorithm\n\n");
    printf("Policy: evict the page UNUSED for the longest time, because recent\n");
    printf("        use is the best simple predictor of imminent use.\n\n");
    printf("Reference string: ");
    for (int i = 0; i < CLASSIC_LEN; i++) printf("%d ", classic_string[i]);
    printf("\n\nSimulation with %d frames  ('.' = empty)\n\n", nframes);

    printf("Ref | ");
    for (int i = 0; i < nframes; i++) printf(" F%-2d", i);
    printf(" | Result   Detail\n----+-");
    for (int i = 0; i < nframes; i++) printf("----");
    printf("-+------------------------------\n");

    Stats s = run_lru(classic_string, CLASSIC_LEN, nframes, 1);

    printf("\n  Page hits %d | page faults %d\n", s.hits, s.faults);
    printf("  Hit ratio %.2f%% | miss ratio %.2f%%\n", s.hit_ratio, s.miss_ratio);

    printf("\n  Stack-property check (the anomaly FIFO showed):\n");
    int previous = -1, anomaly = 0;
    for (int f = 1; f <= 5; f++) {
        int faults = run_lru(classic_string, CLASSIC_LEN, f, 0).faults;
        printf("    %d frame(s): %2d faults", f, faults);
        if (previous != -1 && faults > previous) { printf("   <-- ANOMALY"); anomaly = 1; }
        printf("\n");
        previous = faults;
    }
    if (!anomaly)
        printf("  No anomaly, as theory predicts: LRU is a stack algorithm, so the\n"
               "  pages held with N frames are always a subset of those held with\n"
               "  N+1, and extra memory can only ever help.\n");
}

/* ===================== DEMO 4: STATISTICS AND COMPARISON ==================
 * Requirement 2.1(3) and the evidence behind deliverable 2.2(3).
 * ========================================================================== */

/* Deterministic generator - see the header note on reproducibility. */
static unsigned long lcg_state = 12345UL;
static unsigned long lcg_next(void)
{
    lcg_state = (1103515245UL * lcg_state + 12345UL) & 0x7FFFFFFFUL;
    return lcg_state;
}

/* A hot working set re-read constantly while cold pages stream past once
   each - the pattern that separates LRU from FIFO. */
static int build_working_set(int *out)
{
    int n = 0, next_cold = 0;
    lcg_state = 2024UL;
    for (int i = 0; i < 100; i++) {
        if (lcg_next() % 5 == 0) out[n++] = 3 + (next_cold++ % 9);
        else                     out[n++] = (int)(lcg_next() % 3);
    }
    return n;
}

/* Uniform random over 10 pages: no locality, nothing to predict. */
static int build_random(int *out)
{
    lcg_state = 999UL;
    for (int i = 0; i < 96; i++) out[i] = (int)(lcg_next() % 10);
    return 96;
}

static void bar(int value, int max_value, int width)
{
    int filled = (max_value > 0) ? (value * width) / max_value : 0;
    printf("[");
    for (int i = 0; i < width; i++) putchar(i < filled ? '#' : ' ');
    printf("]");
}

static void compare_workload(const char *name, const int *refs, int len, int focus)
{
    printf("\n  --- %s (%d references) ---\n\n", name, len);
    printf("  Frames |   FIFO      |    LRU      |   CLOCK     |    OPT\n");
    printf("         |  flt  hit%%  |  flt  hit%%  |  flt  hit%%  |  flt  hit%%\n");
    printf("  -------+-------------+-------------+-------------+------------\n");

    for (int nf = 2; nf <= 6; nf++) {
        Stats f = run_fifo (refs, len, nf, 0);
        Stats l = run_lru  (refs, len, nf, 0);
        Stats c = run_clock(refs, len, nf);
        Stats o = run_opt  (refs, len, nf);
        printf("    %-4d | %4d %6.1f | %4d %6.1f | %4d %6.1f | %4d %6.1f\n",
               nf, f.faults, f.hit_ratio, l.faults, l.hit_ratio,
               c.faults, c.hit_ratio, o.faults, o.hit_ratio);
    }

    Stats f = run_fifo (refs, len, focus, 0);
    Stats l = run_lru  (refs, len, focus, 0);
    Stats c = run_clock(refs, len, focus);
    Stats o = run_opt  (refs, len, focus);
    int mx = f.faults;
    if (l.faults > mx) mx = l.faults;
    if (c.faults > mx) mx = c.faults;

    printf("\n  Page faults at %d frames (shorter is better):\n", focus);
    printf("    FIFO  "); bar(f.faults, mx, 34); printf(" %d\n", f.faults);
    printf("    LRU   "); bar(l.faults, mx, 34); printf(" %d\n", l.faults);
    printf("    CLOCK "); bar(c.faults, mx, 34); printf(" %d\n", c.faults);
    printf("    OPT   "); bar(o.faults, mx, 34); printf(" %d  (lower bound)\n", o.faults);

    if (l.faults < f.faults)
        printf("    -> LRU won by %d fault(s) here.\n", f.faults - l.faults);
    else if (l.faults > f.faults)
        printf("    -> FIFO won by %d fault(s) here.\n", l.faults - f.faults);
    else
        printf("    -> FIFO and LRU tied here.\n");
}

static void demo_statistics(void)
{
    int refs[MAX_REFS];

    printf("\n=== DEMO 4: Page faults, hit/miss ratios and comparison ===\n");
    printf("Requirement 2.1(3) and 2.1(4)\n\n");
    printf("  hit ratio  = hits   / references x 100\n");
    printf("  miss ratio = faults / references x 100   (a miss IS a page fault)\n\n");
    printf("  Four policies on identical inputs: FIFO, LRU, CLOCK (second-chance,\n");
    printf("  what real kernels use) and OPT (needs the future; the lower bound).\n");

    compare_workload("Classic teaching string", classic_string, CLASSIC_LEN, 3);

    int len = build_working_set(refs);
    compare_workload("Working set + streaming (realistic)", refs, len, 4);

    len = build_random(refs);
    compare_workload("Uniform random (no locality)", refs, len, 4);

    printf("\n  Conclusion: which policy wins is a property of the ACCESS PATTERN,\n");
    printf("  not of the algorithm alone. LRU pays off where a hot working set is\n");
    printf("  re-read while other pages stream past; where there is no locality the\n");
    printf("  policies converge and FIFO's much lower cost decides it. Only FIFO\n");
    printf("  can suffer Belady's anomaly. CLOCK tracks LRU at nearly FIFO's cost,\n");
    printf("  which is why it is what production kernels actually implement.\n");
}

/* =============================== MENU ==================================== */

static void print_menu(void)
{
    printf("\n=====================================================\n");
    printf(" Task 2 - Memory Management Simulation\n");
    printf("=====================================================\n");
    printf(" 1. Paging with a configurable page size   [Req 2.1(1)]\n");
    printf(" 2. FIFO page replacement                  [Req 2.1(2)]\n");
    printf(" 3. LRU page replacement                   [Req 2.1(2)]\n");
    printf(" 4. Statistics and algorithm comparison    [Req 2.1(3,4)]\n");
    printf(" 5. Run all of the above\n");
    printf(" 0. Exit\n");
    printf("-----------------------------------------------------\n");
    printf("Choose an option: ");
}

static void run_all(void)
{
    demo_paging(256);
    demo_fifo(3);
    demo_lru(3);
    demo_statistics();
}

/* Returns 1 to keep going, 0 to exit. */
static int dispatch(int choice)
{
    switch (choice) {
        case 1: demo_paging(256);   break;
        case 2: demo_fifo(3);       break;
        case 3: demo_lru(3);        break;
        case 4: demo_statistics();  break;
        case 5: run_all();          break;
        case 0: printf("Goodbye.\n"); return 0;
        default: printf("Invalid option - please choose 0-5.\n");
    }
    return 1;
}

int main(int argc, char **argv)
{
    /* ---- non-interactive modes, used to capture the logs in ../outputs/ -- */
    if (argc > 1) {
        if (strcmp(argv[1], "all") == 0) { run_all(); return EXIT_SUCCESS; }
        int choice = atoi(argv[1]);
        if (choice >= 1 && choice <= 5) { dispatch(choice); return EXIT_SUCCESS; }
        fprintf(stderr, "Usage: %s [all | 1-5]\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* ---- interactive menu ---- */
    for (;;) {
        print_menu();
        int choice;
        if (scanf("%d", &choice) != 1) {      /* EOF or non-numeric input */
            printf("\nNo more input - exiting.\n");
            return EXIT_SUCCESS;
        }
        if (!dispatch(choice)) break;
    }
    return EXIT_SUCCESS;
}
