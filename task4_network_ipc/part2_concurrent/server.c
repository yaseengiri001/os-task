/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * Part 2 of 4: A concurrent server (many clients at once)
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 4.1(3): "Handle multiple concurrent client connections."
 *
 * THE PROBLEM WITH PART 1
 *   Part 1's loop served one client to completion before accepting the next.
 *   A single client that pauses for thirty seconds blocks every other client
 *   for thirty seconds. The server is idle the whole time - it is not short of
 *   CPU, it is stuck inside a blocking recv().
 *
 * THE FIX USED HERE: ONE THREAD PER CLIENT
 *   accept() returns, a new thread is created for that client, and the main
 *   loop goes straight back to accept(). Each conversation blocks only its own
 *   thread. This directly reuses Task 1's threading and mutex work - the same
 *   primitives, applied to a different problem.
 *
 * THE SUBTLE BUG THIS FILE AVOIDS (and it is a genuinely common one)
 *   The obvious way to hand the descriptor to the thread is wrong:
 *
 *       int client_fd = accept(...);
 *       pthread_create(&t, NULL, handler, &client_fd);   // BUG
 *
 *   `client_fd` is a local variable that the NEXT loop iteration overwrites.
 *   The new thread may not have dereferenced the pointer yet, so it can end up
 *   reading the second client's descriptor - two threads then serve the same
 *   connection while another is dropped. It is a race, so it works fine in
 *   testing and fails under load.
 *
 *   The fix is to give each thread its OWN copy, heap-allocated here and freed
 *   by the thread itself once it has taken what it needs.
 *
 * DETACHED THREADS
 *   Each handler is detached, so its resources are reclaimed the moment it
 *   finishes and nobody has to pthread_join() it. Without this, every finished
 *   thread would sit as a zombie holding its stack until joined, and a
 *   long-running server would slowly exhaust memory.
 *
 * SHARED STATE NEEDS A MUTEX
 *   The connection counters below are touched by every thread, so they are
 *   protected by a mutex - for exactly the reason Task 1 Part 2 demonstrated:
 *   `counter++` is read-modify-write and loses updates when it races.
 *
 * WHERE THIS MODEL STOPS SCALING (the C10K problem)
 *   A thread costs around 8 MB of virtual address space for its stack, plus
 *   scheduler overhead. At ten thousand simultaneous connections the machine
 *   spends more time context-switching than working. Servers at that scale use
 *   event-driven I/O instead - epoll on Linux, kqueue on BSD/macOS - where one
 *   thread watches thousands of sockets. Thread-per-client is the right choice
 *   for hundreds of connections and the wrong one for hundreds of thousands.
 *
 * BUILD & RUN
 *   make demo                  # starts the server and 4 simultaneous clients
 *   ./server 9002 30           # serve up to 30 clients then exit
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>    /* nanosleep */
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT        9002
#define BACKLOG             16
#define BUF_SIZE            1024
#define DEFAULT_MAX_CLIENTS 4
#define MAX_CONCURRENT      32   /* refuse beyond this: bounded resources */

/* ---- shared state, protected by one mutex ------------------------------- */

/*
 * Sleep for `us` microseconds.
 *
 * nanosleep() rather than sleep_us(): usleep was declared obsolete in
 * POSIX.1-2001 and REMOVED altogether in POSIX.1-2008, so a strict standards
 * build does not declare it at all. nanosleep is its specified replacement.
 */
static void sleep_us(long us)
{
    struct timespec ts;
    ts.tv_sec  = us / 1000000L;
    ts.tv_nsec = (us % 1000000L) * 1000L;
    nanosleep(&ts, NULL);
}
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static int total_connections   = 0;   /* accepted since start   */
static int active_connections  = 0;   /* being served right now */
static int peak_concurrent     = 0;   /* high-water mark        */
static int messages_handled    = 0;

/* Everything one handler thread needs. Allocated per client - see the header
   note on why a pointer to the loop's local variable would be a race. */
typedef struct {
    int  fd;
    int  id;
    char ip[INET_ADDRSTRLEN];
    int  port;
} ClientJob;

static volatile sig_atomic_t keep_running = 1;
static void handle_sigint(int sig) { (void)sig; keep_running = 0; }

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
 * Line framing for the SERVER side.
 *
 * The server needs this every bit as much as the client does. TCP delivers a
 * byte stream with no message boundaries, so a client that sends "HELLO c1\n"
 * and "SLOW\n" in quick succession may well arrive as ONE recv() containing
 * "HELLO c1\nSLOW\n". Code that just calls recv() and truncates at the first
 * newline silently discards the second command - and only ever does so when
 * the timing happens to coalesce the two, which is why the bug survives
 * testing and appears in production.
 *
 * The buffer lives in the caller's stack frame (one per connection thread),
 * never in a static, because many threads run this concurrently.
 */
typedef struct { char data[BUF_SIZE * 2]; size_t len; } LineBuf;

static ssize_t recv_line(int fd, LineBuf *lb, char *out, size_t outsz)
{
    for (;;) {
        /* Consume a complete line if the buffer already holds one. */
        for (size_t i = 0; i < lb->len; i++) {
            if (lb->data[i] == '\n') {
                size_t linelen = i;
                /* strip a preceding CR so CRLF clients work too */
                if (linelen > 0 && lb->data[linelen - 1] == '\r') linelen--;
                if (linelen >= outsz) linelen = outsz - 1;
                memcpy(out, lb->data, linelen);
                out[linelen] = '\0';

                memmove(lb->data, lb->data + i + 1, lb->len - i - 1);
                lb->len -= i + 1;
                return (ssize_t)linelen;
            }
        }

        /* A line longer than the buffer. Refuse rather than grow: an
           unbounded buffer is a peer-controlled memory exhaustion attack. */
        if (lb->len >= sizeof(lb->data)) return -1;

        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0)  return 0;                       /* clean disconnect */
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        lb->len += (size_t)n;
    }
}

/* Accept only a short, plain label from the client's HELLO. Anything the
   client sends is untrusted, and it ends up in our log output. */
static void sanitise_label(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o < outsz - 1; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||  c == '-' || c == '_')
            out[o++] = c;
    }
    out[o] = '\0';
    if (o == 0) snprintf(out, outsz, "anon");
}

/*
 * The per-client conversation. One instance of this function runs in its own
 * thread for every connected client, so several run at the same time.
 */
static void *client_handler(void *arg)
{
    ClientJob *job = (ClientJob *)arg;
    int  fd = job->fd;
    int  id = job->id;
    char ip[INET_ADDRSTRLEN];
    int  port = job->port;
    snprintf(ip, sizeof(ip), "%s", job->ip);

    /* The job struct was allocated for us; release it now that its contents
       have been copied into this thread's own stack. */
    free(job);

    /* ---- update shared counters under the mutex ---- */
    /* active_connections was incremented by the ACCEPTING thread (see the
       accept site), so that the shutdown wait in main() can never see a
       connection that has been accepted but whose thread has not yet run.
       This thread only reads the count and decrements it at the end. */
    pthread_mutex_lock(&stats_lock);
    int active_now = active_connections;
    pthread_mutex_unlock(&stats_lock);

    LineBuf lb = { {0}, 0 };
    char    buf[BUF_SIZE];

    /*
     * A one-line handshake. The client announces the name it calls itself, so
     * the server's log and the client's log refer to the connection by the
     * same name. Without it the two sides number their connections
     * independently and the logs are needlessly hard to line up.
     */
    char label[32];
    snprintf(label, sizeof(label), "conn%d", id);       /* fallback */

    ssize_t hn = recv_line(fd, &lb, buf, sizeof(buf));
    if (hn > 0 && strncmp(buf, "HELLO ", 6) == 0)
        sanitise_label(buf + 6, label, sizeof(label));

    printf("[server] %s connected from %s:%d (%d active now)\n",
           label, ip, port, active_now);
    fflush(stdout);

    char greeting[160];
    int  glen = snprintf(greeting, sizeof(greeting),
                         "WELCOME %s - you are one of %d active\n",
                         label, active_now);
    send_all(fd, greeting, (size_t)glen);

    /* ---- serve this client until it disconnects ---- */
    int  handled = 0;

    for (;;) {
        ssize_t n = recv_line(fd, &lb, buf, sizeof(buf));
        if (n == 0) break;                       /* clean disconnect */
        if (n < 0) break;                        /* error or oversized line */

        if (strcmp(buf, "QUIT") == 0) {
            send_all(fd, "BYE\n", 4);
            break;
        }

        /* STATS is answered from the shared counters, which is why they need
           the mutex - several threads may be reading them concurrently while
           others are incrementing. */
        if (strcmp(buf, "STATS") == 0) {
            pthread_mutex_lock(&stats_lock);
            char stats[192];
            int  slen = snprintf(stats, sizeof(stats),
                                 "STATS total=%d active=%d peak=%d messages=%d\n",
                                 total_connections, active_connections,
                                 peak_concurrent, messages_handled);
            pthread_mutex_unlock(&stats_lock);
            send_all(fd, stats, (size_t)slen);
            continue;
        }

        /*
         * A deliberate pause. In Part 1 this would have frozen every other
         * client; here it delays only this thread, which is the whole point
         * being demonstrated.
         */
        if (strncmp(buf, "SLOW", 4) == 0) {
            printf("[server] %s is doing slow work "
                   "(others keep running)\n", label);
            fflush(stdout);
            sleep_us(400000);                      /* 0.4 seconds */
            send_all(fd, "SLOW done\n", 10);
            handled++;
            continue;
        }

        char reply[BUF_SIZE + 32];
        int  rlen = snprintf(reply, sizeof(reply), "ECHO [%s] %s\n", label, buf);
        if (send_all(fd, reply, (size_t)rlen) < 0) break;
        handled++;

        pthread_mutex_lock(&stats_lock);
        messages_handled++;
        pthread_mutex_unlock(&stats_lock);
    }

    close(fd);

    pthread_mutex_lock(&stats_lock);
    active_connections--;
    int remaining = active_connections;
    pthread_mutex_unlock(&stats_lock);

    printf("[server] %s disconnected after %d message(s) "
           "(%d still active)\n", label, handled, remaining);
    fflush(stdout);
    return NULL;
}

int main(int argc, char **argv)
{
    /* Line-buffer the log. When stdout is a pipe or a file it is fully
       buffered by default, so log lines can sit unwritten for a long time
       and appear out of order relative to the other process. A server log
       is only useful if it appears as events happen. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int port        = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    int max_clients = (argc > 2) ? atoi(argv[2]) : DEFAULT_MAX_CLIENTS;

    signal(SIGINT,  handle_sigint);
    signal(SIGPIPE, SIG_IGN);      /* a disconnecting client must not kill us */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return EXIT_FAILURE; }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind to port %d failed: %s\n", port, strerror(errno));
        close(listen_fd);
        return EXIT_FAILURE;
    }
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen"); close(listen_fd); return EXIT_FAILURE;
    }

    printf("[server] concurrent server listening on port %d\n", port);
    printf("[server] one thread per client - clients no longer block each other\n");
    printf("[server] accepting up to %d client(s) then exiting\n\n", max_clients);
    fflush(stdout);

    while (keep_running && total_connections < max_clients) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);

        int client_fd = accept(listen_fd, (struct sockaddr *)&caddr, &clen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        /* Bound the resources one server will commit. Without a cap, enough
           simultaneous connections exhaust memory and descriptors - a denial
           of service that costs the attacker almost nothing. */
        pthread_mutex_lock(&stats_lock);
        int active_now = active_connections;
        pthread_mutex_unlock(&stats_lock);

        if (active_now >= MAX_CONCURRENT) {
            const char *msg = "ERROR server busy, try again later\n";
            send_all(client_fd, msg, strlen(msg));
            close(client_fd);
            printf("[server] refused a connection: %d already active\n", active_now);
            continue;
        }

        /* Each thread gets its OWN copy of the job - see the header note. */
        ClientJob *job = malloc(sizeof(ClientJob));
        if (!job) { close(client_fd); continue; }

        /* Count the connection as active HERE, before the handler thread
           exists. Doing it in the handler races with the shutdown wait below:
           on the last connection, main could see zero active and exit,
           killing the handler mid-conversation. */
        pthread_mutex_lock(&stats_lock);
        total_connections++;
        active_connections++;
        if (active_connections > peak_concurrent) peak_concurrent = active_connections;
        job->id = total_connections;
        pthread_mutex_unlock(&stats_lock);

        job->fd   = client_fd;
        job->port = ntohs(caddr.sin_port);
        inet_ntop(AF_INET, &caddr.sin_addr, job->ip, sizeof(job->ip));

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_handler, job) != 0) {
            perror("pthread_create");
            close(client_fd);
            free(job);
            pthread_mutex_lock(&stats_lock);   /* undo the optimistic count */
            active_connections--;
            pthread_mutex_unlock(&stats_lock);
            continue;
        }

        /* Detach: nobody will join this thread, so let the system reclaim it
           automatically when it finishes. */
        pthread_detach(tid);
    }

    /* Give any threads still talking to a client a moment to finish. A
       production server would track them and wait properly; this is a bounded
       demonstration, so a short grace period is enough. */
    for (int i = 0; i < 40; i++) {
        pthread_mutex_lock(&stats_lock);
        int active = active_connections;
        pthread_mutex_unlock(&stats_lock);
        if (active == 0) break;
        sleep_us(100000);
    }

    close(listen_fd);

    printf("\n[server] shutting down\n");
    printf("[server] total connections : %d\n", total_connections);
    printf("[server] peak concurrent   : %d\n", peak_concurrent);
    printf("[server] messages handled  : %d\n", messages_handled);
    printf("[server] peak > 1 confirms clients really were served "
           "simultaneously.\n");
    return EXIT_SUCCESS;
}
