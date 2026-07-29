/*
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 * Part 1 of 4: A paging system with a configurable page size
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 2.1(1): "Implement a paging system with configurable page size."
 *
 *   This program models the part of the OS that turns a VIRTUAL address (the
 *   address a program thinks it is using) into a PHYSICAL address (where the
 *   data really lives in RAM). It does this with a PAGE TABLE, exactly like a
 *   real memory management unit (MMU).
 *
 * THE CORE IDEA: SPLIT AN ADDRESS IN TWO
 *   Virtual memory is cut into fixed-size blocks called PAGES; physical memory
 *   is cut into blocks of the SAME size called FRAMES. Any page can live in any
 *   frame, which is what removes external fragmentation.
 *
 *   Because the page size is a power of two, splitting an address is just bit
 *   manipulation - no division needed, which is why real hardware can do it in
 *   one cycle:
 *
 *       virtual address = | page number | offset |
 *
 *       page number = address >> offset_bits
 *       offset      = address &  (page_size - 1)
 *
 *   Translation then means: look up the page number in the page table to get a
 *   frame number, and keep the offset unchanged:
 *
 *       physical address = (frame number << offset_bits) | offset
 *
 * WHY "CONFIGURABLE" MATTERS (the trade-off this program lets you see)
 *   Small pages  -> less wasted space inside the last page (less INTERNAL
 *                   fragmentation) but a much BIGGER page table.
 *   Large pages  -> a small page table, but more space wasted in the last page.
 *   Run the program with different sizes and the summary prints both effects.
 *
 * WHAT THIS PART DELIBERATELY DOES *NOT* DO
 *   When every frame is occupied this program simply reports that memory is
 *   full. Choosing a VICTIM page to evict is the job of a page replacement
 *   algorithm, which is exactly what Part 2 (FIFO) and Part 3 (LRU) add. This
 *   mirrors Task 1, where Part 1 avoided shared data so that Part 2 could show
 *   why synchronization is needed.
 *
 * BUILD & RUN
 *   make                 # compiles to ./paging
 *   make run             # compiles and runs with the default 256-byte page
 *   ./paging 1024        # run again with a 1 KiB page size
 *   (or manually):  cc -Wall -Wextra -std=c11 -o paging paging.c
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>

#define VIRTUAL_MEM_SIZE  4096   /* bytes of virtual address space           */
#define PHYSICAL_MEM_SIZE 1024   /* bytes of real memory - deliberately small
                                    so that it fills up and we can show the
                                    "no free frame" case                     */
#define MAX_PAGES         1024   /* generous upper bounds so the arrays are   */
#define MAX_FRAMES        1024   /* big enough for any page size we allow     */

/*
 * One entry of the page table. A real page table entry also carries protection
 * bits and a dirty bit; we keep the three fields that matter for this
 * simulation.
 */
typedef struct {
    int valid;        /* 1 = this page is currently loaded in a frame        */
    int frame;        /* which physical frame holds it (only if valid)       */
    int loaded_at;    /* the access number at which it was loaded (for logs)  */
} PageTableEntry;

static PageTableEntry page_table[MAX_PAGES];

/* frame_owner[f] = the page number living in frame f, or -1 if the frame is
   free. This is the OS's "reverse" view of memory and is what lets us print a
   memory map.                                                               */
static int frame_owner[MAX_FRAMES];

/* ---- geometry of the address space, all derived from the page size ------- */
static int page_size;     /* bytes per page (must be a power of two)         */
static int offset_bits;   /* how many low bits of an address are the offset   */
static int num_pages;     /* virtual pages                                    */
static int num_frames;    /* physical frames                                  */

/* ---- counters used by the summary --------------------------------------- */
static int accesses = 0, faults = 0, hits = 0;

/*
 * Return log2(n) for a power of two, or -1 if n is not a power of two.
 * We need this to know how many bits of an address form the offset.
 */
static int log2_exact(int n)
{
    int bits = 0;
    if (n <= 0) return -1;
    while ((n & 1) == 0) { n >>= 1; bits++; }
    return (n == 1) ? bits : -1;   /* anything left over means not a power of 2 */
}

/*
 * Find the first free physical frame, or -1 if memory is completely full.
 * A real kernel keeps a free-frame list; a linear scan is clearer here and the
 * frame count is tiny.
 */
static int find_free_frame(void)
{
    for (int f = 0; f < num_frames; f++)
        if (frame_owner[f] == -1) return f;
    return -1;
}

/*
 * Print the current contents of physical memory. This is the "detailed logging
 * of memory allocation" the brief asks for: at any moment you can see which
 * page occupies which frame.
 */
static void print_memory_map(void)
{
    printf("    memory: [");
    for (int f = 0; f < num_frames; f++) {
        if (frame_owner[f] == -1) printf(" -- ");
        else                      printf(" p%-2d", frame_owner[f]);
    }
    printf(" ]\n");
}

/*
 * Translate ONE virtual address and report what happened.
 * Returns the physical address, or -1 if the access could not be satisfied
 * (memory full and no replacement policy in this part).
 */
static int translate(int virtual_address)
{
    accesses++;

    /* ---- Step 1: is the address even inside the virtual address space? ---
     * A real MMU raises a segmentation fault here. We just refuse it.        */
    if (virtual_address < 0 || virtual_address >= VIRTUAL_MEM_SIZE) {
        printf("  addr %-5d -> INVALID (outside 0..%d)\n",
               virtual_address, VIRTUAL_MEM_SIZE - 1);
        return -1;
    }

    /* ---- Step 2: split the address into page number + offset ------------- */
    int page   = virtual_address >> offset_bits;
    int offset = virtual_address & (page_size - 1);

    /* ---- Step 3: consult the page table ---------------------------------- */
    if (page_table[page].valid) {
        /* PAGE HIT - the page is already resident, translation is immediate. */
        hits++;
        int frame    = page_table[page].frame;
        int physical = (frame << offset_bits) | offset;
        printf("  addr %-5d -> page %-3d offset %-4d | HIT   frame %-3d -> phys %-5d\n",
               virtual_address, page, offset, frame, physical);
        return physical;
    }

    /* PAGE FAULT - the page is not in memory, so the OS must load it. */
    faults++;
    int frame = find_free_frame();
    if (frame == -1) {
        printf("  addr %-5d -> page %-3d offset %-4d | FAULT  no free frame "
               "(replacement needed - see Parts 2 and 3)\n",
               virtual_address, page, offset);
        return -1;
    }

    /* Load the page into the free frame and update BOTH views of memory. */
    page_table[page].valid     = 1;
    page_table[page].frame     = frame;
    page_table[page].loaded_at = accesses;
    frame_owner[frame]         = page;

    int physical = (frame << offset_bits) | offset;
    printf("  addr %-5d -> page %-3d offset %-4d | FAULT  loaded into frame %-3d "
           "-> phys %-5d\n",
           virtual_address, page, offset, frame, physical);
    print_memory_map();
    return physical;
}

/* Print the resident part of the page table - the OS's own bookkeeping. */
static void print_page_table(void)
{
    printf("\nPage table (resident pages only)\n");
    printf("  Page  Valid  Frame  LoadedAtAccess\n");
    printf("  ----  -----  -----  --------------\n");
    for (int p = 0; p < num_pages; p++) {
        if (page_table[p].valid)
            printf("  %-4d  %-5d  %-5d  %-14d\n",
                   p, page_table[p].valid, page_table[p].frame,
                   page_table[p].loaded_at);
    }
}

int main(int argc, char **argv)
{
    /* ---- Configurable page size ------------------------------------------
     * Default 256 bytes; override on the command line, e.g. ./paging 1024.
     * The size MUST be a power of two, because the whole point of paging is
     * that the split is done with a shift and a mask.                        */
    page_size = (argc > 1) ? atoi(argv[1]) : 256;

    offset_bits = log2_exact(page_size);
    if (offset_bits < 0) {
        fprintf(stderr, "Error: page size %d is not a power of two.\n", page_size);
        fprintf(stderr, "Try 64, 128, 256, 512 or 1024.\n");
        return EXIT_FAILURE;
    }
    if (page_size > PHYSICAL_MEM_SIZE) {
        fprintf(stderr, "Error: page size %d is larger than physical memory %d.\n",
                page_size, PHYSICAL_MEM_SIZE);
        return EXIT_FAILURE;
    }

    num_pages  = VIRTUAL_MEM_SIZE  / page_size;
    num_frames = PHYSICAL_MEM_SIZE / page_size;

    for (int p = 0; p < num_pages;  p++) page_table[p].valid = 0;
    for (int f = 0; f < num_frames; f++) frame_owner[f]      = -1;

    printf("=== Paging system with a configurable page size ===\n\n");
    printf("Configuration\n");
    printf("  Page size            : %d bytes (offset uses the low %d bits)\n",
           page_size, offset_bits);
    printf("  Virtual memory       : %d bytes = %d pages\n",
           VIRTUAL_MEM_SIZE, num_pages);
    printf("  Physical memory      : %d bytes = %d frames\n",
           PHYSICAL_MEM_SIZE, num_frames);
    printf("  Page-table entries   : %d\n\n", num_pages);

    printf("Address translation:  page = addr >> %d,  offset = addr & 0x%X\n\n",
           offset_bits, page_size - 1);

    /* ---- A sample stream of virtual addresses ----------------------------
     * Chosen to show, in order: a first-touch fault, a hit on the SAME page
     * at a different offset, faults on new pages, a repeat hit, an address
     * outside the address space, and finally memory filling up.             */
    int stream[] = { 0, 100, 260, 1000, 100, 2500, 5000, 3000, 3500, 4000, 300 };
    int n = (int)(sizeof(stream) / sizeof(stream[0]));

    printf("Translating %d virtual addresses\n", n);
    printf("---------------------------------------------------------------\n");
    for (int i = 0; i < n; i++)
        translate(stream[i]);

    print_page_table();

    /* ---- Summary, including the fragmentation trade-off ------------------ */
    int frames_used = 0;
    for (int f = 0; f < num_frames; f++)
        if (frame_owner[f] != -1) frames_used++;

    printf("\nSummary\n");
    printf("  Accesses             : %d\n", accesses);
    printf("  Page hits            : %d\n", hits);
    printf("  Page faults          : %d\n", faults);
    printf("  Frames used          : %d of %d\n", frames_used, num_frames);
    printf("  Memory utilisation   : %.1f%%\n",
           100.0 * frames_used / num_frames);

    printf("\nTrade-off at this page size\n");
    printf("  Page-table entries   : %d   (smaller pages -> a bigger table)\n",
           num_pages);
    printf("  Worst-case internal fragmentation per process: %d bytes\n",
           page_size - 1);
    printf("  (the last page of a process is almost never completely full)\n");
    printf("\nRe-run with a different power of two to compare, e.g. ./paging 1024\n");

    return EXIT_SUCCESS;
}
