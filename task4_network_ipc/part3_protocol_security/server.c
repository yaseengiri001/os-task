/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * Part 3 of 4: Protocol, authentication, validation and error handling
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 4.1(2): "Implement a simple protocol for data exchange."
 *   Requirement 4.1(4): "Implement basic security measures (authentication,
 *                        data validation)."
 *   Requirement 4.1(5): "Demonstrate proper error handling and connection
 *                        management."
 *
 * WHY A PROTOCOL IS NEEDED AT ALL
 *   Parts 1 and 2 just echoed text. Once the two sides need to do anything
 *   useful they must agree in advance on the shape of every message, what each
 *   reply means, and what happens when something is wrong. That agreement IS
 *   the protocol. Without one, each side guesses, and the guesses diverge.
 *
 * THE PROTOCOL: LINE-BASED, TEXT, REQUEST/RESPONSE
 *   Every message is one line ending in \n:
 *
 *       request   COMMAND [argument]...
 *       response  <status> <text>
 *
 *   Statuses borrow the idea used by SMTP, FTP and HTTP - a machine-readable
 *   code with human-readable text after it:
 *
 *       200 OK           the request succeeded
 *       331 CHALLENGE    authentication challenge issued
 *       400 BAD REQUEST  malformed - the client's fault, do not retry as-is
 *       401 UNAUTHORISED authentication required or failed
 *       429 TOO MANY     rate limited
 *       500 ERROR        the server's fault
 *
 *   Text was chosen over a binary format because it can be read directly with
 *   telnet or netcat, which makes the protocol far easier to debug and to
 *   demonstrate. A binary format would be more compact and is what a
 *   high-throughput service would use.
 *
 * AUTHENTICATION: CHALLENGE-RESPONSE, NOT A PASSWORD ON THE WIRE
 *   The obvious design - client sends "LOGIN alice secret" - has two serious
 *   flaws. The password is exposed to anyone who can observe the traffic, and
 *   an attacker who records the exchange can simply REPLAY it later without
 *   ever knowing the password.
 *
 *   Instead:
 *       1. client:  AUTH alice
 *       2. server:  331 CHALLENGE <32 random hex bytes>
 *       3. client:  RESPONSE <HMAC-SHA256(password, nonce)>
 *       4. server recomputes the same HMAC and compares in constant time
 *
 *   The password itself never crosses the network. The nonce is fresh and
 *   single-use, so a recorded response is worthless against the next
 *   connection. This is the same idea behind CRAM-MD5 and Digest
 *   authentication.
 *
 *   The honest limitation: this proves the client knows the password, but it
 *   does nothing to encrypt the traffic that follows, and it cannot stop an
 *   active attacker in the middle from relaying the whole exchange. Real
 *   deployments run the protocol inside TLS, which solves both. Stating that
 *   plainly matters more than pretending the design is complete.
 *
 * VALIDATION: EVERYTHING FROM THE NETWORK IS HOSTILE
 *   Input arriving over a socket is attacker-controlled by definition. Every
 *   message is therefore checked for length, for a known command, for the
 *   right number of arguments, and for permitted characters, BEFORE it is
 *   acted on. Unknown commands are rejected rather than ignored.
 *
 * CONNECTION MANAGEMENT
 *   - a receive TIMEOUT, so a client that connects and then says nothing
 *     cannot hold a thread open indefinitely (the "slowloris" attack)
 *   - a cap on failed authentication attempts per connection
 *   - every path closes its socket, including every error path
 *   - SIGPIPE ignored, so a client vanishing mid-write cannot kill the server
 *
 * BUILD & RUN
 *   make demo
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


#include "../../task3_filesystem_security/common/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>   /* va_list, used by reply() */
#include <string.h>
#include <time.h>     /* time/gmtime/strftime for the TIME command */
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT        9003
#define BACKLOG             16
#define BUF_SIZE            1024
#define MAX_LINE            512     /* longest request we will accept   */
#define DEFAULT_MAX_CLIENTS 3
#define MAX_AUTH_FAILURES   3
#define RECV_TIMEOUT_SEC    10
#define NONCE_LEN           16

/* The account database. Passwords appear here in the clear ONLY because
   challenge-response requires the server to know the secret in order to
   recompute the HMAC. That is the real trade-off of this scheme: it protects
   the password on the WIRE at the cost of needing it recoverable on the
   SERVER. A password hash cannot be used, because the client would have to
   send something derived from the hash and the hash would then BE the
   password. Task 3's salted-hash storage and this design solve genuinely
   different problems, and a system that needs both uses TLS plus hashes. */

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
typedef struct {
    const char *username;
    const char *password;
} Account;

static const Account accounts[] = {
    { "alice", "correct-horse-battery" },
    { "bob",   "Tr0ub4dor&3xyz"        },
};
static const int account_count = (int)(sizeof(accounts) / sizeof(accounts[0]));

static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static int total_connections = 0, active_connections = 0;
static int auth_successes = 0, auth_failures = 0, bad_requests = 0;

typedef struct { int fd; int id; char ip[INET_ADDRSTRLEN]; int port; } ClientJob;

static volatile sig_atomic_t keep_running = 1;
static void handle_sigint(int sig) { (void)sig; keep_running = 0; }

/* ===================== TRANSPORT HELPERS ================================= */

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
 * Send one formatted response line.
 *
 * CAREFUL WITH vsnprintf's RETURN VALUE. It returns the length the output
 * WOULD have been, not the length actually written. When the output is
 * truncated that value is LARGER than the buffer, so the obvious
 *
 *     int n = vsnprintf(line, sizeof(line), ...);
 *     line[n++] = '\n';                      // writes past the end
 *
 * is a buffer overflow that only triggers on unusually long input - which is
 * to say, exactly the input an attacker supplies. The return value is
 * therefore clamped before it is used as an index.
 */
static int reply(int fd, const char *fmt, ...)
{
    char line[BUF_SIZE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n > sizeof(line) - 2) n = (int)(sizeof(line) - 2);   /* truncated */
    line[n++] = '\n';
    line[n]   = '\0';
    return send_all(fd, line, (size_t)n);
}

typedef struct { char data[BUF_SIZE * 2]; size_t len; } LineBuf;

/* Line framing - TCP has no message boundaries. See part1/client.c. */
static ssize_t recv_line(int fd, LineBuf *lb, char *out, size_t outsz)
{
    for (;;) {
        for (size_t i = 0; i < lb->len; i++) {
            if (lb->data[i] == '\n') {
                size_t linelen = i;
                if (linelen > 0 && lb->data[linelen - 1] == '\r') linelen--;
                if (linelen >= outsz) linelen = outsz - 1;
                memcpy(out, lb->data, linelen);
                out[linelen] = '\0';
                memmove(lb->data, lb->data + i + 1, lb->len - i - 1);
                lb->len -= i + 1;
                return (ssize_t)linelen;
            }
        }
        if (lb->len >= sizeof(lb->data)) return -2;   /* oversized line */

        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0) return 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -3;  /* timeout */
            return -1;
        }
        lb->len += (size_t)n;
    }
}

/*
 * Close a connection in a way that lets the peer actually RECEIVE our last
 * reply.
 *
 * This matters more than it looks. If we call close() while unread data is
 * still sitting in the receive queue - which is exactly the situation after we
 * reject an over-long request that the client is still transmitting - the
 * kernel does not send a polite FIN. It sends an RST, and an RST DISCARDS
 * anything we had queued for transmission. The carefully worded "400 BAD
 * REQUEST" is thrown away and the client sees only a dropped connection.
 *
 * The fix is the standard graceful shutdown:
 *   1. shutdown(SHUT_WR) - send FIN, so our pending reply is flushed first
 *   2. drain whatever the peer is still sending, and discard it
 *   3. close once the peer has finished
 *
 * The drain is bounded in both time and iterations, because a peer that never
 * stops talking must not be able to hold this thread open - which would simply
 * reintroduce the denial of service we were defending against.
 */
static void graceful_close(int fd)
{
    shutdown(fd, SHUT_WR);

    struct timeval quick = { 1, 0 };          /* short, bounded drain */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &quick, sizeof(quick));

    char sink[1024];
    for (int i = 0; i < 64; i++) {
        ssize_t n = recv(fd, sink, sizeof(sink), 0);
        if (n <= 0) break;                    /* EOF, error or timeout */
    }
    close(fd);
}

static int secure_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) { close(fd); return -1; }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ===================== VALIDATION ========================================
 * Everything below treats the peer as hostile. These checks run BEFORE any
 * request is acted upon.
 * ======================================================================== */

/* A username must be short and alphanumeric. An allow-list refuses anything
   unanticipated by default, rather than trying to enumerate what is bad. */
static int valid_username(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 32) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||  c == '_' || c == '-')) return 0;
    }
    return 1;
}

/* A response must be exactly 64 lowercase hex characters - the size of a
   SHA-256 digest. Checking the SHAPE before doing any work means malformed
   input is rejected cheaply. */
static int valid_hex_digest(const char *s)
{
    if (strlen(s) != SHA256_DIGEST_SIZE * 2) return 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return 0;
    return 1;
}

/* Echo payloads may contain spaces but must be printable and bounded. Control
   characters are refused because they corrupt logs and terminals. */
static int valid_payload(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 256) return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) return 0;
    return 1;
}

static const Account *find_account(const char *user)
{
    for (int i = 0; i < account_count; i++)
        if (strcmp(accounts[i].username, user) == 0) return &accounts[i];
    return NULL;
}

/* ===================== THE CONNECTION STATE MACHINE ======================= */

typedef enum { ST_NEW, ST_CHALLENGED, ST_AUTHENTICATED } State;

static void *client_handler(void *arg)
{
    ClientJob *job = (ClientJob *)arg;
    int  fd = job->fd, id = job->id, port = job->port;
    char ip[INET_ADDRSTRLEN];
    snprintf(ip, sizeof(ip), "%s", job->ip);
    free(job);

    /* NOTE: active_connections was incremented by the ACCEPTING thread, not
       here. See the comment at the accept site - incrementing it here is a
       race against the shutdown check in main(). This thread only decrements
       it, once the conversation is genuinely over. */

    printf("[server] conn %d from %s:%d\n", id, ip, port);
    fflush(stdout);

    /*
     * A receive timeout. Without it, a client that connects and then sends
     * nothing holds this thread forever; a few hundred such connections
     * exhaust the server using almost no resources on the attacker's side.
     * That is the slowloris denial-of-service.
     */
    struct timeval tv = { RECV_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    LineBuf lb  = { {0}, 0 };
    State   st  = ST_NEW;
    char    pending_user[64] = "";
    uint8_t nonce[NONCE_LEN];
    char    nonce_hex[NONCE_LEN * 2 + 1] = "";
    int     failures = 0;
    int     requests = 0;

    reply(fd, "200 READY ST5004CEM protocol v1 - send AUTH <user> or HELP");

    for (;;) {
        char line[MAX_LINE];
        ssize_t n = recv_line(fd, &lb, line, sizeof(line));

        if (n == 0)  { printf("[server] conn %d closed by peer\n", id); break; }
        if (n == -3) { reply(fd, "408 TIMEOUT no request within %d seconds",
                             RECV_TIMEOUT_SEC);
                       printf("[server] conn %d timed out\n", id); break; }
        if (n == -2) { reply(fd, "400 BAD REQUEST line too long");
                       pthread_mutex_lock(&stats_lock); bad_requests++;
                       pthread_mutex_unlock(&stats_lock);
                       printf("[server] conn %d sent an oversized line\n", id);
                       break; }
        if (n < 0)   { printf("[server] conn %d receive error\n", id); break; }

        requests++;

        /* ---- Reject an over-long request before parsing it -------------- */
        if (strlen(line) > MAX_LINE - 1) {
            reply(fd, "400 BAD REQUEST too long");
            continue;
        }

        /* ---- Split into a command and at most two arguments -------------- */
        char work[MAX_LINE];
        snprintf(work, sizeof(work), "%s", line);
        char *cmd  = strtok(work, " ");
        char *arg1 = strtok(NULL, " ");
        char *arg2 = strtok(NULL, "");     /* rest of line, spaces included */

        if (cmd == NULL) { reply(fd, "400 BAD REQUEST empty"); continue; }

        printf("[server] conn %d >> %.60s\n", id, line);
        fflush(stdout);

        /* ---- HELP: available without authenticating -------------------- */
        if (strcmp(cmd, "HELP") == 0) {
            reply(fd, "200 OK commands: HELP AUTH RESPONSE ECHO TIME WHOAMI QUIT");
            continue;
        }

        /* ---- QUIT: always allowed -------------------------------------- */
        if (strcmp(cmd, "QUIT") == 0) {
            reply(fd, "200 BYE");
            printf("[server] conn %d quit\n", id);
            break;
        }

        /* ---- AUTH <user>: issue a fresh single-use challenge ------------ */
        if (strcmp(cmd, "AUTH") == 0) {
            if (arg1 == NULL || arg2 != NULL) {
                reply(fd, "400 BAD REQUEST usage: AUTH <username>");
                continue;
            }
            if (!valid_username(arg1)) {
                reply(fd, "400 BAD REQUEST invalid username format");
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }

            /*
             * A challenge is issued whether or not the account exists, and the
             * eventual failure message is identical either way. Refusing here
             * would tell an attacker which usernames are real.
             */
            snprintf(pending_user, sizeof(pending_user), "%s", arg1);
            if (secure_random(nonce, NONCE_LEN) != 0) {
                reply(fd, "500 ERROR no entropy available");
                break;
            }
            hex_encode(nonce, NONCE_LEN, nonce_hex);
            st = ST_CHALLENGED;
            reply(fd, "331 CHALLENGE %s", nonce_hex);
            continue;
        }

        /* ---- RESPONSE <hex>: verify HMAC(password, nonce) --------------- */
        if (strcmp(cmd, "RESPONSE") == 0) {
            if (st != ST_CHALLENGED) {
                reply(fd, "400 BAD REQUEST send AUTH <username> first");
                continue;
            }
            if (arg1 == NULL || arg2 != NULL || !valid_hex_digest(arg1)) {
                reply(fd, "400 BAD REQUEST expected 64 hex characters");
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }

            const Account *acct = find_account(pending_user);
            uint8_t expected[SHA256_DIGEST_SIZE];
            char    expected_hex[SHA256_DIGEST_SIZE * 2 + 1];

            /* Compute an HMAC even for an unknown account, using a dummy
               secret, so that a bad username costs the same time as a bad
               password and cannot be distinguished by timing. */
            const char *secret = acct ? acct->password : "no-such-account";
            hmac_sha256((const uint8_t *)secret, strlen(secret),
                        (const uint8_t *)nonce_hex, strlen(nonce_hex), expected);
            hex_encode(expected, SHA256_DIGEST_SIZE, expected_hex);

            int ok = acct != NULL &&
                     constant_time_equal((const uint8_t *)expected_hex,
                                         (const uint8_t *)arg1,
                                         SHA256_DIGEST_SIZE * 2);

            /* The nonce is single-use no matter what happens, so a captured
               response can never be replayed against this connection. */
            st = ST_NEW;
            nonce_hex[0] = '\0';

            if (ok) {
                st = ST_AUTHENTICATED;
                pthread_mutex_lock(&stats_lock); auth_successes++;
                pthread_mutex_unlock(&stats_lock);
                reply(fd, "200 OK authenticated as %s", pending_user);
                printf("[server] conn %d authenticated as %s\n", id, pending_user);
            } else {
                failures++;
                pthread_mutex_lock(&stats_lock); auth_failures++;
                pthread_mutex_unlock(&stats_lock);
                if (failures >= MAX_AUTH_FAILURES) {
                    reply(fd, "429 TOO MANY failed attempts - closing");
                    printf("[server] conn %d dropped after %d auth failures\n",
                           id, failures);
                    break;
                }
                /* One message for every kind of failure - no enumeration. */
                reply(fd, "401 UNAUTHORISED invalid credentials (%d of %d)",
                      failures, MAX_AUTH_FAILURES);
            }
            continue;
        }

        /* ---- Everything below requires authentication ------------------- */
        if (st != ST_AUTHENTICATED) {
            reply(fd, "401 UNAUTHORISED authenticate first");
            continue;
        }

        if (strcmp(cmd, "ECHO") == 0) {
            /* arg1 holds the first word, arg2 the rest. Rejoin them. */
            char payload[MAX_LINE] = "";
            if (arg1) snprintf(payload, sizeof(payload), "%s%s%s",
                               arg1, arg2 ? " " : "", arg2 ? arg2 : "");
            if (!valid_payload(payload)) {
                reply(fd, "400 BAD REQUEST payload must be 1-256 printable chars");
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }
            reply(fd, "200 OK %s", payload);
            continue;
        }

        if (strcmp(cmd, "TIME") == 0) {
            time_t t = time(NULL);
            struct tm *tm = gmtime(&t);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);
            reply(fd, "200 OK %s", ts);
            continue;
        }

        if (strcmp(cmd, "WHOAMI") == 0) {
            reply(fd, "200 OK %s", pending_user);
            continue;
        }

        /* Unknown commands are REFUSED, not ignored. Silently accepting
           anything unrecognised hides both bugs and probing. */
        reply(fd, "400 BAD REQUEST unknown command");
        pthread_mutex_lock(&stats_lock); bad_requests++;
        pthread_mutex_unlock(&stats_lock);
    }

    /* Every path reaches here, including every error path, so the socket is
       never leaked. graceful_close ensures the peer receives whatever reply we
       sent immediately before deciding to disconnect. */
    graceful_close(fd);

    pthread_mutex_lock(&stats_lock);
    active_connections--;
    pthread_mutex_unlock(&stats_lock);

    printf("[server] conn %d finished (%d requests)\n", id, requests);
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
    signal(SIGPIPE, SIG_IGN);

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
        close(listen_fd); return EXIT_FAILURE;
    }
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen"); close(listen_fd); return EXIT_FAILURE;
    }

    printf("[server] protocol server listening on port %d\n", port);
    printf("[server] challenge-response auth; passwords never cross the wire\n");
    printf("[server] serving up to %d connection(s)\n\n", max_clients);
    fflush(stdout);

    while (keep_running && total_connections < max_clients) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&caddr, &clen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept"); break;
        }

        ClientJob *job = malloc(sizeof(ClientJob));
        if (!job) { close(client_fd); continue; }

        /*
         * Count this connection as ACTIVE here, in the accepting thread,
         * before the handler thread is even created.
         *
         * Doing it inside the handler instead is a real race, and a subtle
         * one. On the last permitted connection this loop exits immediately
         * after pthread_create and goes to the shutdown wait below. If the new
         * thread has not yet run its first instruction, the wait sees
         * active_connections == 0, concludes everything has finished, and
         * returns from main - which terminates the process and the handler
         * along with it, mid-conversation. The client then sees a reset
         * connection instead of the reply the server was about to send.
         *
         * Incrementing before the thread exists makes the count correct from
         * the instant the connection is accepted, so the shutdown wait can
         * never observe a connection that has not started yet.
         */
        pthread_mutex_lock(&stats_lock);
        total_connections++;
        active_connections++;
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
        pthread_detach(tid);
    }

    /*
     * Wait for connections still in progress before exiting.
     *
     * Returning from main() terminates the process and every detached handler
     * thread with it, mid-conversation. The grace period must therefore exceed
     * the per-connection receive timeout, or a client that is slow (or is being
     * deliberately slow) can be cut off before the server has finished telling
     * it what went wrong - which is exactly what a test of the oversized-line
     * path looks like. A production server would track its threads and join
     * them rather than rely on a timeout.
     */
    for (int i = 0; i < (RECV_TIMEOUT_SEC + 5) * 10; i++) {
        pthread_mutex_lock(&stats_lock);
        int active = active_connections;
        pthread_mutex_unlock(&stats_lock);
        if (active == 0) break;
        sleep_us(100000);
    }
    close(listen_fd);

    printf("\n[server] shutting down\n");
    printf("[server] connections     : %d\n", total_connections);
    printf("[server] auth successes  : %d\n", auth_successes);
    printf("[server] auth failures   : %d\n", auth_failures);
    printf("[server] bad requests    : %d\n", bad_requests);
    return EXIT_SUCCESS;
}
