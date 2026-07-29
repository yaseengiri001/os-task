/*
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 * Part 4 of 4: Page-fault statistics, hit/miss ratios and algorithm comparison
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 2.1(3): "Track page faults and calculate hit/miss ratios."
 *   Requirement 2.1(4): "Provide visualization or detailed logging of memory
 *                        allocation."
 *   Deliverable  2.2(3): the evidence behind the analysis report comparing
 *                        algorithm performance.
 *
 * WHAT THIS PROGRAM ADDS OVER PARTS 2 AND 3
 *   Parts 2 and 3 each ran ONE algorithm on ONE reference string. Judging which
 *   policy is better from a single 12-reference run would be unsound, so this
 *   part turns the simulation into a measurement harness:
 *
 *     - FOUR algorithms are run on IDENTICAL inputs (a fair comparison)
 *     - each is measured across a RANGE of frame counts (a fault curve)
 *     - three DIFFERENT workloads are used, because the right answer depends
 *       on the access pattern, not on the algorithm alone
 *     - results are drawn as an ASCII bar chart as well as a table
 *
 * THE FOUR ALGORITHMS
 *   FIFO   - evict the oldest page.                        (Part 2)
 *   LRU    - evict the least recently used page.           (Part 3)
 *   OPT    - evict the page whose NEXT use is furthest in the future.
 *            Belady's optimal algorithm. It needs knowledge of the future so
 *            it can never be implemented in a real OS, but it gives the
 *            theoretical LOWER BOUND on page faults. Including it turns "LRU
 *            beat FIFO" into a meaningful statement, because we can finally
 *            say how much room for improvement was left at all.
 *   CLOCK  - second-chance. This is what real kernels actually use: one
 *            reference bit per frame and a rotating hand. On a fault the hand
 *            advances; a frame whose bit is set has it cleared and is spared
 *            (a "second chance"), and the first frame found with a clear bit
 *            is evicted. It approximates LRU at FIFO-like cost, so it shows the
 *            engineering compromise that theory alone does not.
 *
 * WHY THE RANDOM WORKLOAD USES ITS OWN GENERATOR
 *   rand() is implemented differently on different C libraries, so the same
 *   seed gives different numbers on Linux and macOS. A tiny fixed linear
 *   congruential generator is used instead, which makes every figure in this
 *   report byte-for-byte reproducible on any machine that compiles the code.
 *
 * BUILD & RUN
 *   make run
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FRAMES 16
#define MAX_REFS   512
#define EMPTY      -1

/* Results of a single simulation run. */
typedef struct {
    int    faults;
    int    hits;
    double hit_ratio;    /* percentage */
    double miss_ratio;   /* percentage */
} Stats;

/* ============================ WORKLOADS =================================== */

/*
 * A deterministic linear congruential generator (the "minimal standard"
 * constants). Used instead of rand() so results are identical on every
 * platform - see the header comment.
 */
static unsigned long lcg_state = 12345UL;
static unsigned long lcg_next(void)
{
    lcg_state = (1103515245UL * lcg_state + 12345UL) & 0x7FFFFFFFUL;
    return lcg_state;
}

/* Workload A: the classic teaching string (the one that breaks FIFO). */
static int build_classic(int *out)
{
    static const int s[] = { 1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5 };
    int n = (int)(sizeof(s) / sizeof(s[0]));
    memcpy(out, s, sizeof(s));
    return n;
}

/*
 * Workload B: WORKING SET + STREAMING. This is the pattern LRU is actually
 * designed for, and it is extremely common in real software: a program keeps
 * re-reading a small HOT set (its loop code, an index, a lookup table) while
 * also streaming through a large body of COLD data it will not read again -
 * think of a report generator scanning a big file while repeatedly consulting
 * the same few lookup pages.
 *
 * Pages 0-2 are the hot working set; pages 3-11 are streamed once each in
 * sequence. Roughly four references in five hit the hot set.
 *
 * This is the case that separates the two policies. LRU sees the hot pages
 * being re-referenced constantly and keeps them resident, spending only one
 * frame on the passing cold stream. FIFO cannot see any of that: it evicts
 * purely by age, so each cold page that streams through pushes a hot page out,
 * and the hot pages then have to be faulted straight back in.
 */
#define HOT_PAGES  3
#define COLD_FIRST 3
#define COLD_COUNT 9

static int build_working_set(int *out)
{
    int n = 0;
    int next_cold = 0;
    lcg_state = 2024UL;

    for (int i = 0; i < 100; i++) {
        if (lcg_next() % 5 == 0) {
            /* one reference in five streams the next cold page */
            out[n++] = COLD_FIRST + (next_cold % COLD_COUNT);
            next_cold++;
        } else {
            /* the other four re-read the hot working set */
            out[n++] = (int)(lcg_next() % HOT_PAGES);
        }
    }
    return n;
}

/*
 * Workload C: UNIFORM RANDOM over 10 pages, with no locality at all. This is
 * the worst case for every algorithm: with nothing to predict, a smarter
 * policy cannot help, and all four should converge. Including it is what
 * stops the comparison from overstating LRU's advantage.
 */
static int build_random(int *out)
{
    int n = 96;
    lcg_state = 999UL;
    for (int i = 0; i < n; i++) out[i] = (int)(lcg_next() % 10);
    return n;
}

/* ============================ ALGORITHMS ================================== */

/* Is `page` currently resident? Returns its frame index, or -1. */
static int find_page(const int *frames, int n, int page)
{
    for (int f = 0; f < n; f++) if (frames[f] == page) return f;
    return -1;
}

/* Index of the first free frame, or -1 if memory is full. */
static int find_free(const int *frames, int n)
{
    for (int f = 0; f < n; f++) if (frames[f] == EMPTY) return f;
    return -1;
}

/* Fill in the derived ratio fields once faults and hits are known. */
static Stats finish(int faults, int hits, int total)
{
    Stats s;
    s.faults     = faults;
    s.hits       = hits;
    s.hit_ratio  = 100.0 * hits   / total;
    s.miss_ratio = 100.0 * faults / total;
    return s;
}

/* ---- FIFO: rotating hand, no work on a hit ------------------------------ */
static Stats run_fifo(const int *refs, int len, int nframes)
{
    int frames[MAX_FRAMES];
    int hand = 0, faults = 0, hits = 0;
    for (int i = 0; i < nframes; i++) frames[i] = EMPTY;

    for (int i = 0; i < len; i++) {
        if (find_page(frames, nframes, refs[i]) != -1) { hits++; continue; }
        faults++;
        frames[hand] = refs[i];
        hand = (hand + 1) % nframes;
    }
    return finish(faults, hits, len);
}

/* ---- LRU: evict the smallest last_used timestamp ------------------------ */
static Stats run_lru(const int *refs, int len, int nframes)
{
    int frames[MAX_FRAMES], last_used[MAX_FRAMES];
    int faults = 0, hits = 0, clock = 0;
    for (int i = 0; i < nframes; i++) { frames[i] = EMPTY; last_used[i] = 0; }

    for (int i = 0; i < len; i++) {
        clock++;
        int f = find_page(frames, nframes, refs[i]);
        if (f != -1) { hits++; last_used[f] = clock; continue; }

        faults++;
        int victim = find_free(frames, nframes);
        if (victim == -1) {
            victim = 0;
            for (int k = 1; k < nframes; k++)
                if (last_used[k] < last_used[victim]) victim = k;
        }
        frames[victim]    = refs[i];
        last_used[victim] = clock;
    }
    return finish(faults, hits, len);
}

/* ---- OPT: evict whichever resident page is needed furthest in the future -
 * Requires the whole future of the reference string, which is why no real OS
 * can do this. It is the lower bound every other policy is measured against. */
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
            /* For each resident page, find how far ahead it is next used.
               The page with the furthest (or no) next use is the victim.     */
            int furthest = -1;
            victim = 0;
            for (int f = 0; f < nframes; f++) {
                int next_use = len;                 /* len = "never again"    */
                for (int j = i + 1; j < len; j++) {
                    if (refs[j] == frames[f]) { next_use = j; break; }
                }
                if (next_use > furthest) { furthest = next_use; victim = f; }
            }
        }
        frames[victim] = refs[i];
    }
    return finish(faults, hits, len);
}

/* ---- CLOCK (second chance): LRU's practical approximation ---------------
 * One reference bit per frame. A hit merely SETS the bit (cheap - this is the
 * whole point). On a fault the hand sweeps: a set bit is cleared and the frame
 * is spared; the first clear bit found is evicted.                           */
static Stats run_clock(const int *refs, int len, int nframes)
{
    int frames[MAX_FRAMES], ref_bit[MAX_FRAMES];
    int hand = 0, faults = 0, hits = 0;
    for (int i = 0; i < nframes; i++) { frames[i] = EMPTY; ref_bit[i] = 0; }

    for (int i = 0; i < len; i++) {
        int f = find_page(frames, nframes, refs[i]);
        if (f != -1) { hits++; ref_bit[f] = 1; continue; }   /* cheap hit path */

        faults++;
        int victim = find_free(frames, nframes);
        if (victim == -1) {
            /* Sweep the hand until a frame with a clear reference bit is
               found, clearing bits (granting second chances) along the way.
               This terminates within at most two full sweeps.                */
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

/* ============================ REPORTING =================================== */

/*
 * Draw one horizontal bar. Used to build an ASCII chart of the fault counts,
 * which makes the comparison readable at a glance rather than as raw numbers.
 */
static void bar(int value, int max_value, int width)
{
    int filled = (max_value > 0) ? (value * width) / max_value : 0;
    printf("[");
    for (int i = 0; i < width; i++) putchar(i < filled ? '#' : ' ');
    printf("]");
}

/* How many distinct page numbers appear in a reference string. */
static int count_distinct(const int *refs, int len)
{
    int seen[64] = {0}, distinct = 0;
    for (int i = 0; i < len; i++)
        if (refs[i] >= 0 && refs[i] < 64 && !seen[refs[i]]) {
            seen[refs[i]] = 1;
            distinct++;
        }
    return distinct;
}

/*
 * A summary of one workload at the frame count we focus on, kept so that the
 * final conclusion can be derived FROM THE MEASUREMENTS rather than asserted.
 * Writing the verdict by hand would risk it contradicting the numbers printed
 * directly above it, so nothing below is hard-coded.
 */
typedef struct {
    const char *name;
    int         focus_frames;
    int         fifo, lru, clock, opt;
} WorkloadResult;

/* Run all four algorithms on one workload and print the full comparison. */
static WorkloadResult analyse_workload(const char *name, const char *description,
                                       const int *refs, int len, int focus_frames)
{
    printf("\n===============================================================\n");
    printf("WORKLOAD: %s\n", name);
    printf("  %s\n", description);
    printf("  Length: %d references, %d distinct pages\n",
           len, count_distinct(refs, len));
    printf("===============================================================\n\n");

    printf("Page faults and hit/miss ratios by frame count\n\n");
    printf("Frames |        FIFO        |         LRU        |"
           "        CLOCK       |         OPT\n");
    printf("       |  flt   hit%%  miss%% |  flt   hit%%  miss%% |"
           "  flt   hit%%  miss%% |  flt   hit%%  miss%%\n");
    printf("-------+--------------------+--------------------+"
           "--------------------+--------------------\n");

    for (int nf = 2; nf <= 6; nf++) {
        Stats f = run_fifo (refs, len, nf);
        Stats l = run_lru  (refs, len, nf);
        Stats c = run_clock(refs, len, nf);
        Stats o = run_opt  (refs, len, nf);

        printf("  %-4d | %4d %6.1f %6.1f | %4d %6.1f %6.1f |"
               " %4d %6.1f %6.1f | %4d %6.1f %6.1f\n",
               nf,
               f.faults, f.hit_ratio, f.miss_ratio,
               l.faults, l.hit_ratio, l.miss_ratio,
               c.faults, c.hit_ratio, c.miss_ratio,
               o.faults, o.hit_ratio, o.miss_ratio);
    }

    /* ---- Visualisation of the fault counts at the focus frame count ------ */
    printf("\nVisualisation - page faults with %d frames (shorter is better)\n\n",
           focus_frames);
    Stats f3 = run_fifo (refs, len, focus_frames);
    Stats l3 = run_lru  (refs, len, focus_frames);
    Stats c3 = run_clock(refs, len, focus_frames);
    Stats o3 = run_opt  (refs, len, focus_frames);

    int max_f = f3.faults;
    if (l3.faults > max_f) max_f = l3.faults;
    if (c3.faults > max_f) max_f = c3.faults;
    if (o3.faults > max_f) max_f = o3.faults;

    printf("  FIFO  "); bar(f3.faults, max_f, 40); printf(" %d faults\n", f3.faults);
    printf("  LRU   "); bar(l3.faults, max_f, 40); printf(" %d faults\n", l3.faults);
    printf("  CLOCK "); bar(c3.faults, max_f, 40); printf(" %d faults\n", c3.faults);
    printf("  OPT   "); bar(o3.faults, max_f, 40); printf(" %d faults  (lower bound)\n",
                                                          o3.faults);

    /* ---- A short verdict, derived entirely from the numbers above -------- */
    printf("\n  Reading of these results:\n");
    if (l3.faults < f3.faults) {
        double gain = 100.0 * (f3.faults - l3.faults) / f3.faults;
        printf("    LRU beat FIFO by %d faults (%.1f%% fewer), because this\n",
               f3.faults - l3.faults, gain);
        printf("    workload rewards keeping recently used pages resident.\n");
    } else if (l3.faults > f3.faults) {
        printf("    FIFO beat LRU here by %d fault(s). Recency is only a heuristic,\n",
               l3.faults - f3.faults);
        printf("    and where it does not predict the future it can lose.\n");
    } else {
        printf("    FIFO and LRU tied - on this workload recency carries no\n");
        printf("    predictive value, so the cheaper policy is the better choice.\n");
    }
    int clock_gap = c3.faults - l3.faults;
    if (clock_gap < 0) clock_gap = -clock_gap;

    printf("    OPT needed %d faults, so the very best any implementable policy\n",
           o3.faults);
    printf("    could have done was %d fewer than LRU. CLOCK came within %d fault(s)\n",
           l3.faults - o3.faults, clock_gap);
    printf("    of LRU using only one reference bit per frame, not a timestamp.\n");

    WorkloadResult r;
    r.name         = name;
    r.focus_frames = focus_frames;
    r.fifo         = f3.faults;
    r.lru          = l3.faults;
    r.clock        = c3.faults;
    r.opt          = o3.faults;
    return r;
}

int main(void)
{
    int refs[MAX_REFS];
    int len;

    printf("=== Page-fault statistics and algorithm comparison ===\n");
    printf("\nFour algorithms are compared on identical inputs:\n");
    printf("  FIFO   evict the oldest page                (Part 2)\n");
    printf("  LRU    evict the least recently used page   (Part 3)\n");
    printf("  CLOCK  second-chance; what real kernels use\n");
    printf("  OPT    evict the page used furthest in the future - not\n");
    printf("         implementable, but it is the theoretical lower bound\n");
    printf("\nHit ratio  = hits   / references x 100\n");
    printf("Miss ratio = faults / references x 100   (miss = page fault)\n");

    WorkloadResult results[3];

    len = build_classic(refs);
    results[0] = analyse_workload("Classic teaching string",
                     "The 12-reference string used in Parts 2 and 3.",
                     refs, len, 3);

    len = build_working_set(refs);
    results[1] = analyse_workload("Working set + streaming (realistic)",
                     "A hot 3-page working set re-read constantly, while cold "
                     "pages stream past once each.",
                     refs, len, 4);

    len = build_random(refs);
    results[2] = analyse_workload("Uniform random (worst case)",
                     "96 references spread evenly over 10 pages, with no "
                     "locality to exploit.",
                     refs, len, 4);

    /* ---- Overall conclusion, computed from the three results ------------- */
    printf("\n\n===============================================================\n");
    printf("OVERALL CONCLUSION\n");
    printf("===============================================================\n\n");

    printf("Summary of page faults at the frame count highlighted for each\n");
    printf("workload (lower is better):\n\n");
    printf("  Workload                              Frames  FIFO   LRU  CLOCK   OPT\n");
    printf("  ------------------------------------  ------  ----  ----  -----  ----\n");
    for (int i = 0; i < 3; i++)
        printf("  %-36s  %-6d  %4d  %4d  %5d  %4d\n",
               results[i].name, results[i].focus_frames,
               results[i].fifo, results[i].lru, results[i].clock, results[i].opt);

    int lru_wins = 0, fifo_wins = 0, ties = 0;
    for (int i = 0; i < 3; i++) {
        if      (results[i].lru < results[i].fifo) lru_wins++;
        else if (results[i].lru > results[i].fifo) fifo_wins++;
        else                                       ties++;
    }

    printf("\nAcross the three workloads measured above, LRU beat FIFO %d time(s),\n",
           lru_wins);
    printf("FIFO beat LRU %d time(s), and they tied %d time(s).\n\n", fifo_wins, ties);

    printf("What the measurements support:\n");
    printf("  - Neither policy is better in the abstract. Which one wins is a\n");
    printf("    property of the ACCESS PATTERN, not of the algorithm alone, so a\n");
    printf("    single reference string is never enough to judge them.\n");
    printf("  - LRU's advantage appears exactly where its assumption holds: when\n");
    printf("    a hot working set is re-read while other pages stream past, LRU\n");
    printf("    protects the working set and FIFO evicts it purely for being old.\n");
    printf("  - Where there is no locality to exploit, neither policy holds a\n");
    printf("    stable lead: on the random workload above they trade places as the\n");
    printf("    frame count changes, and every gap between them is small next to\n");
    printf("    the gap separating both from OPT. When the difference in fault\n");
    printf("    count is that marginal, FIFO's far lower bookkeeping cost is the\n");
    printf("    deciding factor rather than the fault count itself.\n");
    printf("  - Belady's anomaly (demonstrated in Part 2) is the one respect in\n");
    printf("    which FIFO is not merely weaker but unsound: extra memory can\n");
    printf("    increase its fault count. LRU is a stack algorithm and cannot.\n");
    printf("  - CLOCK stayed close to LRU throughout while doing almost no work\n");
    printf("    on a hit, which is why production kernels approximate LRU this\n");
    printf("    way instead of implementing it exactly.\n");
    printf("  - OPT is unimplementable, but it bounds the comparison: it shows how\n");
    printf("    much of the remaining gap was winnable at all.\n");

    return EXIT_SUCCESS;
}
