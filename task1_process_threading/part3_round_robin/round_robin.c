/*
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 * Part 3 of 4: Round-robin CPU scheduler simulation
 * -----------------------------------------------------------------------------
 * GOAL
 *   Requirement 1.1(3): "Demonstrate process scheduling by implementing a
 *   simple round-robin scheduler simulation."
 *
 * WHAT ROUND-ROBIN (RR) IS
 *   The CPU can only run one process at a time, so the OS shares it. In RR
 *   every process gets a fixed slice of CPU time called the TIME QUANTUM.
 *   Processes wait in a circular "ready queue":
 *       - the process at the front runs for up to one quantum
 *       - if it still needs more CPU, it goes to the BACK of the queue
 *       - the next process runs, and so on, round and round
 *   This is FAIR (no process is starved) and gives good response time, which
 *   is why interactive/time-sharing systems use it.
 *
 * WHAT WE MEASURE (standard scheduling metrics)
 *   Completion time = when the process finishes
 *   Turnaround time = completion - arrival        (total time in the system)
 *   Waiting time    = turnaround - burst          (time spent NOT running)
 *
 * NOTE ON ORDERING (a classic RR detail)
 *   If a process arrives at the exact instant another is preempted, the newly
 *   ARRIVED process joins the queue BEFORE the preempted one is put back.
 *   This is the standard convention and this simulation follows it.
 *
 * BUILD & RUN
 *   make run
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_PROC   32
#define MAX_SEG    512   /* Gantt-chart segments (one per time slice)          */
#define QCAP       64    /* circular ready-queue capacity                      */

/* A process/job to be scheduled. */
typedef struct {
    int pid;          /* process id, e.g. 1 -> "P1"                            */
    int arrival;      /* time it enters the system                            */
    int burst;        /* total CPU time it needs                              */
    int remaining;    /* CPU time still left (counts down as it runs)         */
    int completion;   /* filled in when it finishes                           */
    int turnaround;
    int waiting;
} Process;

/* ---- a small circular queue holding process array-indices ---- */
static int  q[QCAP];
static int  qhead = 0, qtail = 0, qcount = 0;

static void q_push(int idx) { q[qtail] = idx; qtail = (qtail + 1) % QCAP; qcount++; }
static int  q_pop(void)     { int x = q[qhead]; qhead = (qhead + 1) % QCAP; qcount--; return x; }
static int  q_empty(void)   { return qcount == 0; }

/* Gantt chart storage: which pid ran from [start,end). */
static int seg_pid[MAX_SEG], seg_start[MAX_SEG], seg_end[MAX_SEG];
static int seg_count = 0;

int main(void)
{
    /* ---- Sample workload. Change these to test other scenarios. ---------- */
    Process p[] = {
        /* pid, arrival, burst */
        { 1, 0, 5, 0,0,0,0 },
        { 2, 1, 3, 0,0,0,0 },
        { 3, 2, 6, 0,0,0,0 },
        { 4, 3, 1, 0,0,0,0 },
    };
    int n = (int)(sizeof(p) / sizeof(p[0]));
    int quantum = 2;

    for (int i = 0; i < n; i++) p[i].remaining = p[i].burst;

    /* Order in which to CONSIDER arrivals: by arrival time, ties by pid.
       (Selection sort on a tiny array - clarity over speed.)               */
    int order[MAX_PROC];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++)
        for (int j = i + 1; j < n; j++)
            if (p[order[j]].arrival <  p[order[i]].arrival ||
               (p[order[j]].arrival == p[order[i]].arrival &&
                p[order[j]].pid     <  p[order[i]].pid))
            { int t = order[i]; order[i] = order[j]; order[j] = t; }

    int added[MAX_PROC] = {0};   /* has this process been put in the queue? */
    int completed = 0;
    int now = 0;

    /* Helper (inline via a macro-free loop): enqueue everything that has
       arrived by 'now' and is not yet queued, in arrival order.            */
    #define ENQUEUE_ARRIVALS()                                   \
        for (int k = 0; k < n; k++) {                            \
            int idx = order[k];                                  \
            if (!added[idx] && p[idx].arrival <= now) {          \
                q_push(idx); added[idx] = 1;                     \
            } else if (p[idx].arrival > now) {                   \
                break; /* order[] is sorted, so we can stop */   \
            }                                                    \
        }

    printf("Round-robin scheduling  (time quantum = %d)\n\n", quantum);

    ENQUEUE_ARRIVALS();

    while (completed < n) {
        if (q_empty()) {
            /* CPU idle: jump forward to the next process's arrival. */
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

        now            += slice;     /* CPU runs process i for 'slice' units  */
        p[i].remaining -= slice;

        /* record this run for the Gantt chart */
        seg_pid[seg_count] = p[i].pid;
        seg_start[seg_count] = start;
        seg_end[seg_count] = now;
        seg_count++;

        /* new arrivals enter the queue BEFORE the preempted process re-joins */
        ENQUEUE_ARRIVALS();

        if (p[i].remaining > 0) {
            q_push(i);               /* not done -> back of the queue         */
        } else {
            p[i].completion = now;   /* done -> record its metrics            */
            p[i].turnaround = p[i].completion - p[i].arrival;
            p[i].waiting    = p[i].turnaround - p[i].burst;
            completed++;
        }
    }
    #undef ENQUEUE_ARRIVALS

    /* -------- Gantt chart (merge consecutive slices of the same pid) ------- */
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

    /* ----------------------------- results table -------------------------- */
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

    return EXIT_SUCCESS;
}
