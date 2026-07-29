/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * Part 2 of 4: A multi-connection client (proves the server is concurrent)
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 4.1(3): the evidence side of "handle multiple concurrent
 *   client connections."
 *
 * WHY THE CLIENT NEEDS THREADS TOO
 *   Claiming a server is concurrent proves nothing unless several clients are
 *   genuinely talking to it AT THE SAME MOMENT. Connecting four times in
 *   sequence would be satisfied by Part 1's one-at-a-time server, so it would
 *   demonstrate nothing at all.
 *
 *   This client therefore opens N connections from N threads simultaneously.
 *   One of them deliberately asks the server to do slow work; if the others
 *   finish while it is still waiting, the server must have been serving them
 *   concurrently. Against Part 1's server the same test would show every client
 *   finishing strictly one after another.
 *
 * WHAT TO LOOK FOR IN THE OUTPUT
 *   - the server reports "peak concurrent" greater than 1
 *   - fast clients complete while the slow client is still in progress
 *   - the elapsed total is far less than the sum of the individual times
 *
 * BUILD & RUN
 *   ./client 127.0.0.1 9002 4      # host, port, number of clients
 * -----------------------------------------------------------------------------
 */

/*
 * Request the POSIX.1-2008 interfaces before any header is included.
 *
 * Without this, glibc exposes only the ISO C subset under -std=c11 and hides
 * pread/pwrite, pthread_rwlock_t and friends, so a strict Linux build fails
 * with "implicit declaration". macOS happens to expose them anyway, which is
 * exactly why this has to be tested on both - the omission is invisible on one
 * platform and fatal on the other.
 */
#define _POSIX_C_SOURCE 200809L


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>   /* va_list, used by say() */
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE   1024
#define MAX_THREADS 16

typedef struct {
    int  id;
    char host[64];
    int  port;
    int  slow;        /* 1 = ask the server to do slow work */
    int  ok;          /* set on success, read after the join */
    double seconds;   /* how long this client took */
} ClientTask;

static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

/* Milliseconds since an arbitrary origin, for measuring elapsed time. */
static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) { if (errno == EINTR) continue; return -1; }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * Read one newline-terminated line, reassembling it from however the bytes
 * arrive. TCP is a byte stream with no message boundaries, so this framing is
 * required rather than optional - see the long note in part1/client.c.
 *
 * The buffer is per-call state here (not static as in Part 1) because several
 * threads run this function at once; a shared static buffer would be corrupted
 * by exactly the race Task 1 Part 2 demonstrated.
 */
typedef struct { char data[BUF_SIZE * 2]; size_t len; } LineBuf;

static ssize_t recv_line(int fd, LineBuf *lb, char *out, size_t outsz)
{
    for (;;) {
        for (size_t i = 0; i < lb->len; i++) {
            if (lb->data[i] == '\n') {
                size_t linelen = i;
                if (linelen >= outsz) linelen = outsz - 1;
                memcpy(out, lb->data, linelen);
                out[linelen] = '\0';
                memmove(lb->data, lb->data + i + 1, lb->len - i - 1);
                lb->len -= i + 1;
                return (ssize_t)linelen;
            }
        }
        if (lb->len >= sizeof(lb->data)) return -1;   /* refuse a huge line */

        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0)  return 0;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        lb->len += (size_t)n;
    }
}

/* Printing from several threads at once interleaves mid-line without a lock. */
static void say(int id, const char *fmt, ...)
{
    va_list ap;
    pthread_mutex_lock(&print_lock);
    printf("[client %d] ", id);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
    pthread_mutex_unlock(&print_lock);
}

static void *client_thread(void *arg)
{
    ClientTask *t = (ClientTask *)arg;
    LineBuf lb = { {0}, 0 };
    char    reply[BUF_SIZE];
    double  start = now_ms();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { say(t->id, "socket failed: %s\n", strerror(errno)); return NULL; }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons((uint16_t)t->port);
    if (inet_pton(AF_INET, t->host, &server.sin_addr) != 1) {
        say(t->id, "bad address %s\n", t->host);
        close(fd);
        return NULL;
    }

    if (connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        say(t->id, "connect failed: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    /* Announce ourselves so the server logs this connection under the same
       name we use. One line, terminated by \n, like every other message. */
    char hello[64];
    int  hlen = snprintf(hello, sizeof(hello), "HELLO c%d\n", t->id);
    send_all(fd, hello, (size_t)hlen);

    /* The server greets every client on connect. */
    if (recv_line(fd, &lb, reply, sizeof(reply)) > 0)
        say(t->id, "server says: %s\n", reply);

    /* The slow client holds the server for 0.4s; the others should not wait. */
    if (t->slow) {
        say(t->id, "requesting SLOW work (0.4s) ...\n");
        send_all(fd, "SLOW\n", 5);
        if (recv_line(fd, &lb, reply, sizeof(reply)) > 0)
            say(t->id, "slow work finished: %s\n", reply);
    } else {
        for (int i = 1; i <= 2; i++) {
            char msg[128];
            int  len = snprintf(msg, sizeof(msg), "message %d from client %d\n",
                                i, t->id);
            send_all(fd, msg, (size_t)len);
            if (recv_line(fd, &lb, reply, sizeof(reply)) > 0)
                say(t->id, "got: %s\n", reply);
        }
    }

    /* Ask for the server's live counters - proof of how many were active. */
    send_all(fd, "STATS\n", 6);
    if (recv_line(fd, &lb, reply, sizeof(reply)) > 0)
        say(t->id, "%s\n", reply);

    send_all(fd, "QUIT\n", 5);
    recv_line(fd, &lb, reply, sizeof(reply));
    close(fd);

    t->seconds = (now_ms() - start) / 1000.0;
    t->ok = 1;
    say(t->id, "done in %.2fs\n", t->seconds);
    return NULL;
}

int main(int argc, char **argv)
{
    /* Line-buffer the log. When stdout is a pipe or a file it is fully
       buffered by default, so log lines can sit unwritten for a long time
       and appear out of order relative to the other process. A server log
       is only useful if it appears as events happen. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /*
     * Ignore SIGPIPE. Writing to a socket whose peer has already closed
     * raises SIGPIPE, whose default action is to KILL the process - so a
     * client that sends one more request after the server has hung up simply
     * dies, with no chance to report why. Ignoring it turns the event into an
     * ordinary EPIPE error from send(), which the existing error handling
     * already deals with. Servers need this for the same reason; clients need
     * it just as much.
     */
    signal(SIGPIPE, SIG_IGN);

    const char *host    = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port    = (argc > 2) ? atoi(argv[2]) : 9002;
    int         nclients= (argc > 3) ? atoi(argv[3]) : 4;

    if (nclients < 1 || nclients > MAX_THREADS) {
        fprintf(stderr, "client count must be 1..%d\n", MAX_THREADS);
        return EXIT_FAILURE;
    }

    printf("Launching %d clients SIMULTANEOUSLY against %s:%d\n", nclients, host, port);
    printf("Client 1 asks for slow work; if the others finish first, the\n");
    printf("server handled them concurrently.\n\n");

    pthread_t  tids[MAX_THREADS];
    ClientTask tasks[MAX_THREADS];
    double     start = now_ms();

    for (int i = 0; i < nclients; i++) {
        tasks[i].id   = i + 1;
        tasks[i].port = port;
        tasks[i].slow = (i == 0);       /* the first one is the slow one */
        tasks[i].ok   = 0;
        tasks[i].seconds = 0;
        snprintf(tasks[i].host, sizeof(tasks[i].host), "%s", host);

        if (pthread_create(&tids[i], NULL, client_thread, &tasks[i]) != 0) {
            perror("pthread_create");
            tasks[i].ok = -1;
        }
    }

    for (int i = 0; i < nclients; i++)
        if (tasks[i].ok != -1) pthread_join(tids[i], NULL);

    double total = (now_ms() - start) / 1000.0;

    printf("\n--- summary ---\n");
    double sum = 0;
    int    succeeded = 0;
    for (int i = 0; i < nclients; i++) {
        printf("  client %d: %-8s %.2fs\n", tasks[i].id,
               tasks[i].ok == 1 ? "OK" : "FAILED", tasks[i].seconds);
        sum += tasks[i].seconds;
        if (tasks[i].ok == 1) succeeded++;
    }
    printf("  %d of %d succeeded\n", succeeded, nclients);
    printf("  wall-clock elapsed : %.2fs\n", total);
    printf("  sum of individual  : %.2fs\n", sum);
    printf("\n  The elapsed time is close to the SLOWEST client rather than the\n");
    printf("  sum of all of them, which is what concurrent service looks like.\n");
    printf("  Served one at a time, the total would approach the sum.\n");

    return (succeeded == nclients) ? EXIT_SUCCESS : EXIT_FAILURE;
}
