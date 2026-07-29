/*
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 * COMBINED: the complete client-server application (server side)
 * -----------------------------------------------------------------------------
 * GOAL
 *   Parts 1-3 introduced one idea at a time. This is the single client-server
 *   application the brief asks for, with all of them working together:
 *
 *     Requirement 4.1(1)  server and client over sockets      -> this + client.c
 *     Requirement 4.1(2)  a protocol for data exchange        -> the command table
 *     Requirement 4.1(3)  multiple concurrent clients         -> thread per client
 *     Requirement 4.1(4)  authentication and data validation  -> AUTH/RESPONSE,
 *                                                                validate_*()
 *     Requirement 4.1(5)  error handling and connection mgmt  -> status codes,
 *                                                                timeouts,
 *                                                                graceful_close
 *
 * WHAT THE SERVICE ACTUALLY DOES
 *   It is a small key-value store. Each authenticated user gets a private
 *   namespace: STORE saves a value, FETCH retrieves it, LIST names them, DELETE
 *   removes one. That makes the access-control question real rather than
 *   decorative - there is now something worth protecting, and "can user A read
 *   user B's key?" has a correct answer that the server must enforce.
 *
 * CONCURRENCY AND THE SHARED STORE
 *   Every client runs in its own thread, so the store is shared mutable state
 *   reachable from many threads at once. It is protected by a READER-WRITER
 *   lock rather than a plain mutex: FETCH and LIST only read, and any number of
 *   readers may proceed together, while STORE and DELETE take the write lock
 *   exclusively. A plain mutex would be correct but would serialise reads
 *   needlessly, and reads dominate this workload.
 *
 * THE FULL PROTOCOL IS DOCUMENTED IN PROTOCOL.md (deliverable 4.2(2)).
 *
 * BUILD & RUN
 *   make                        # builds server and client
 *   make demo                   # scripted end-to-end run, no input needed
 *   ./server 9000               # run the server on its own
 *   ./client 127.0.0.1 9000     # interactive client
 * -----------------------------------------------------------------------------
 */

#include "../../task3_filesystem_security/common/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT        9000
#define BACKLOG             32
#define BUF_SIZE            1024
#define MAX_LINE            512
#define MAX_KEY             32
#define MAX_VALUE           256
#define MAX_ENTRIES         64
#define MAX_AUTH_FAILURES   3
#define MAX_CONCURRENT      32
#define RECV_TIMEOUT_SEC    15
#define NONCE_LEN           16
#define DEFAULT_MAX_CLIENTS 0        /* 0 = run until interrupted */

/* ---- accounts ----------------------------------------------------------
 * Passwords are held in the clear because challenge-response requires the
 * server to recompute the HMAC, which needs the secret itself. That is this
 * scheme's genuine trade-off: it protects the password ON THE WIRE at the cost
 * of needing it recoverable ON THE SERVER. Task 3 stores salted hashes because
 * it solves the opposite problem. A real system runs a hash-based login inside
 * TLS and gets both.                                                         */
typedef struct { const char *user; const char *pass; } Account;
static const Account accounts[] = {
    { "alice", "correct-horse-battery" },
    { "bob",   "Tr0ub4dor&3xyz"        },
};
static const int account_count = (int)(sizeof(accounts) / sizeof(accounts[0]));

/* ---- the shared key-value store ---------------------------------------- */
typedef struct {
    char owner[32];
    char key[MAX_KEY + 1];
    char value[MAX_VALUE + 1];
    int  used;
} Entry;

static Entry          store[MAX_ENTRIES];
static pthread_rwlock_t store_lock = PTHREAD_RWLOCK_INITIALIZER;

/* ---- statistics, under their own mutex --------------------------------- */
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static int total_connections = 0, active_connections = 0, peak_concurrent = 0;
static int auth_ok = 0, auth_fail = 0, bad_requests = 0, commands_served = 0;

typedef struct { int fd, id, port; char ip[INET_ADDRSTRLEN]; } ClientJob;

static volatile sig_atomic_t keep_running = 1;
static void handle_sigint(int sig) { (void)sig; keep_running = 0; }

/* ===================== TRANSPORT ========================================= */

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

/* vsnprintf returns the length it WOULD have written, which exceeds the
   buffer when truncated. Clamp before using it as an index, or a long reply
   writes past the end of `line`. */
static int reply(int fd, const char *fmt, ...)
{
    char line[BUF_SIZE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n > sizeof(line) - 2) n = (int)(sizeof(line) - 2);
    line[n++] = '\n';
    line[n]   = '\0';
    return send_all(fd, line, (size_t)n);
}

typedef struct { char data[BUF_SIZE * 2]; size_t len; } LineBuf;

/*
 * Line framing. TCP is a byte stream with no message boundaries, so messages
 * must be reassembled; see the long note in part1/client.c.
 *
 * Return values are deliberately all distinct:
 *     >= 0  the length of the line (0 IS a legitimate empty line)
 *       -1  receive error
 *       -2  line longer than the buffer
 *       -3  timed out waiting for input
 *       -4  the peer closed the connection
 *
 * Using 0 for "peer closed" - as the simpler parts do, where an empty line
 * never occurs - would make an empty line indistinguishable from a disconnect,
 * and the server would hang up on a client that merely pressed Enter.
 */
static ssize_t recv_line(int fd, LineBuf *lb, char *out, size_t outsz)
{
    for (;;) {
        for (size_t i = 0; i < lb->len; i++) {
            if (lb->data[i] == '\n') {
                size_t len = i;
                if (len > 0 && lb->data[len - 1] == '\r') len--;
                if (len >= outsz) len = outsz - 1;
                memcpy(out, lb->data, len);
                out[len] = '\0';
                memmove(lb->data, lb->data + i + 1, lb->len - i - 1);
                lb->len -= i + 1;
                return (ssize_t)len;
            }
        }
        if (lb->len >= sizeof(lb->data)) return -2;

        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0) return -4;                       /* peer closed */
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -3;
            return -1;
        }
        lb->len += (size_t)n;
    }
}

/*
 * Close so the peer actually receives our final reply.
 *
 * close() with unread data still queued makes the kernel send RST instead of
 * FIN, and RST discards anything we had queued for transmission - so the error
 * we just carefully wrote never arrives. shutdown() then a bounded drain
 * avoids that. The drain is bounded because a peer that never stops talking
 * must not be able to hold this thread open.
 */
static void graceful_close(int fd)
{
    shutdown(fd, SHUT_WR);
    struct timeval quick = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &quick, sizeof(quick));
    char sink[1024];
    for (int i = 0; i < 64; i++)
        if (recv(fd, sink, sizeof(sink), 0) <= 0) break;
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
 * Everything arriving on a socket is attacker-controlled. Each check is an
 * ALLOW-LIST: it states what is permitted and refuses everything else, so
 * anything unanticipated fails closed rather than open.
 * ======================================================================== */

static int valid_username(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 32) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int valid_key(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > MAX_KEY) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}

/* Values may contain spaces but must be printable ASCII and bounded.
   Control characters are refused: they corrupt logs and terminals, and are a
   standard vehicle for log-injection. */
static int valid_value(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > MAX_VALUE) return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) return 0;
    return 1;
}

static int valid_hex_digest(const char *s)
{
    if (strlen(s) != SHA256_DIGEST_SIZE * 2) return 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return 0;
    return 1;
}

static const Account *find_account(const char *u)
{
    for (int i = 0; i < account_count; i++)
        if (strcmp(accounts[i].user, u) == 0) return &accounts[i];
    return NULL;
}

/* ===================== THE STORE =========================================
 * Every entry belongs to exactly one user, and lookups always match on BOTH
 * owner and key. A user therefore cannot reach another user's data even by
 * guessing the key name - the isolation is a property of the lookup itself
 * rather than a check that could be forgotten at one call site.
 * ======================================================================== */

static Entry *find_entry_locked(const char *owner, const char *key)
{
    for (int i = 0; i < MAX_ENTRIES; i++)
        if (store[i].used &&
            strcmp(store[i].owner, owner) == 0 &&
            strcmp(store[i].key,   key)   == 0) return &store[i];
    return NULL;
}

static int store_put(const char *owner, const char *key, const char *value)
{
    pthread_rwlock_wrlock(&store_lock);          /* exclusive: we mutate */
    Entry *e = find_entry_locked(owner, key);
    if (!e) {
        for (int i = 0; i < MAX_ENTRIES; i++)
            if (!store[i].used) { e = &store[i]; break; }
        if (!e) { pthread_rwlock_unlock(&store_lock); return -1; }  /* full */
        e->used = 1;
        snprintf(e->owner, sizeof(e->owner), "%s", owner);
        snprintf(e->key,   sizeof(e->key),   "%s", key);
    }
    snprintf(e->value, sizeof(e->value), "%s", value);
    pthread_rwlock_unlock(&store_lock);
    return 0;
}

static int store_get(const char *owner, const char *key, char *out, size_t n)
{
    pthread_rwlock_rdlock(&store_lock);          /* shared: readers concur */
    Entry *e = find_entry_locked(owner, key);
    if (e) snprintf(out, n, "%s", e->value);
    int found = e != NULL;
    pthread_rwlock_unlock(&store_lock);
    return found;
}

static int store_del(const char *owner, const char *key)
{
    pthread_rwlock_wrlock(&store_lock);
    Entry *e = find_entry_locked(owner, key);
    if (e) { e->used = 0; e->value[0] = '\0'; }
    int found = e != NULL;
    pthread_rwlock_unlock(&store_lock);
    return found;
}

/* Build a space-separated list of the caller's own keys. */
static int store_list(const char *owner, char *out, size_t outsz)
{
    pthread_rwlock_rdlock(&store_lock);
    size_t used = 0;
    int    count = 0;
    out[0] = '\0';
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (!store[i].used || strcmp(store[i].owner, owner) != 0) continue;
        size_t need = strlen(store[i].key) + 1;
        if (used + need >= outsz) break;          /* never overrun the buffer */
        if (count) { out[used++] = ' '; out[used] = '\0'; }
        strcat(out, store[i].key);
        used = strlen(out);
        count++;
    }
    pthread_rwlock_unlock(&store_lock);
    return count;
}

/* ===================== CONNECTION HANDLER ================================ */

typedef enum { ST_NEW, ST_CHALLENGED, ST_AUTH } State;

static void *client_handler(void *arg)
{
    ClientJob *job = (ClientJob *)arg;
    int  fd = job->fd, id = job->id, port = job->port;
    char ip[INET_ADDRSTRLEN];
    snprintf(ip, sizeof(ip), "%s", job->ip);
    free(job);

    /* active_connections was incremented by the accepting thread - see the
       comment at the accept site for why doing it here would be a race. */
    printf("[server] conn %d open  from %s:%d\n", id, ip, port);

    struct timeval tv = { RECV_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    LineBuf lb = { {0}, 0 };
    State   st = ST_NEW;
    char    user[64]  = "";
    char    nonce_hex[NONCE_LEN * 2 + 1] = "";
    uint8_t nonce[NONCE_LEN];
    int     failures = 0, served = 0;

    reply(fd, "200 READY kvstore/1.0 - HELP for commands");

    for (;;) {
        char line[MAX_LINE];
        ssize_t n = recv_line(fd, &lb, line, sizeof(line));

        if (n == -4) { printf("[server] conn %d closed by peer\n", id); break; }
        if (n == -3) { reply(fd, "408 TIMEOUT idle for %d seconds", RECV_TIMEOUT_SEC);
                       printf("[server] conn %d timed out\n", id); break; }
        if (n == -2) { reply(fd, "400 BAD REQUEST line too long");
                       pthread_mutex_lock(&stats_lock); bad_requests++;
                       pthread_mutex_unlock(&stats_lock);
                       printf("[server] conn %d sent an oversized line\n", id);
                       break; }
        if (n < 0)   { printf("[server] conn %d receive error\n", id); break; }
        if (n == 0)  continue;      /* a bare Enter: ignore it, do not hang up */

        served++;
        pthread_mutex_lock(&stats_lock); commands_served++;
        pthread_mutex_unlock(&stats_lock);

        char work[MAX_LINE];
        snprintf(work, sizeof(work), "%s", line);
        char *cmd  = strtok(work, " ");
        char *arg1 = strtok(NULL, " ");
        char *rest = strtok(NULL, "");            /* remainder, spaces kept */

        if (!cmd) { reply(fd, "400 BAD REQUEST empty"); continue; }

        if (strcmp(cmd, "HELP") == 0) {
            reply(fd, "200 OK AUTH RESPONSE STORE FETCH DELETE LIST WHOAMI "
                      "STATS PING QUIT");
            continue;
        }
        if (strcmp(cmd, "PING") == 0) { reply(fd, "200 PONG"); continue; }
        if (strcmp(cmd, "QUIT") == 0) { reply(fd, "200 BYE");
                                        printf("[server] conn %d quit\n", id);
                                        break; }

        /* ---- AUTH <user> : issue a fresh, single-use challenge ---------- */
        if (strcmp(cmd, "AUTH") == 0) {
            if (!arg1 || rest || !valid_username(arg1)) {
                reply(fd, "400 BAD REQUEST usage: AUTH <username>");
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }
            /* A challenge is issued whether or not the account exists, so the
               reply cannot be used to discover which usernames are real. */
            snprintf(user, sizeof(user), "%s", arg1);
            if (secure_random(nonce, NONCE_LEN) != 0) {
                reply(fd, "500 ERROR no entropy"); break;
            }
            hex_encode(nonce, NONCE_LEN, nonce_hex);
            st = ST_CHALLENGED;
            reply(fd, "331 CHALLENGE %s", nonce_hex);
            continue;
        }

        /* ---- RESPONSE <hex> : verify HMAC(password, nonce) -------------- */
        if (strcmp(cmd, "RESPONSE") == 0) {
            if (st != ST_CHALLENGED) {
                reply(fd, "400 BAD REQUEST send AUTH first"); continue;
            }
            if (!arg1 || rest || !valid_hex_digest(arg1)) {
                reply(fd, "400 BAD REQUEST expected 64 hex characters");
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }

            const Account *a = find_account(user);
            /* An unknown account still costs a full HMAC, so the response time
               cannot distinguish "no such user" from "wrong password". */
            const char *secret = a ? a->pass : "no-such-account-placeholder";
            uint8_t mac[SHA256_DIGEST_SIZE];
            char    mac_hex[SHA256_DIGEST_SIZE * 2 + 1];
            hmac_sha256((const uint8_t *)secret, strlen(secret),
                        (const uint8_t *)nonce_hex, strlen(nonce_hex), mac);
            hex_encode(mac, SHA256_DIGEST_SIZE, mac_hex);

            int ok = a && constant_time_equal((const uint8_t *)mac_hex,
                                              (const uint8_t *)arg1,
                                              SHA256_DIGEST_SIZE * 2);

            st = ST_NEW;                 /* the nonce is single-use, always */
            nonce_hex[0] = '\0';

            if (ok) {
                st = ST_AUTH;
                pthread_mutex_lock(&stats_lock); auth_ok++;
                pthread_mutex_unlock(&stats_lock);
                reply(fd, "200 OK authenticated as %s", user);
                printf("[server] conn %d authenticated as %s\n", id, user);
            } else {
                failures++;
                pthread_mutex_lock(&stats_lock); auth_fail++;
                pthread_mutex_unlock(&stats_lock);
                if (failures >= MAX_AUTH_FAILURES) {
                    reply(fd, "429 TOO MANY failed attempts - closing");
                    printf("[server] conn %d dropped after %d auth failures\n",
                           id, failures);
                    break;
                }
                reply(fd, "401 UNAUTHORISED invalid credentials (%d of %d)",
                      failures, MAX_AUTH_FAILURES);
            }
            continue;
        }

        /* ---- everything past here needs a session ----------------------- */
        if (st != ST_AUTH) { reply(fd, "401 UNAUTHORISED authenticate first");
                             continue; }

        if (strcmp(cmd, "WHOAMI") == 0) { reply(fd, "200 OK %s", user); continue; }

        if (strcmp(cmd, "STATS") == 0) {
            pthread_mutex_lock(&stats_lock);
            reply(fd, "200 OK connections=%d active=%d peak=%d commands=%d",
                  total_connections, active_connections, peak_concurrent,
                  commands_served);
            pthread_mutex_unlock(&stats_lock);
            continue;
        }

        if (strcmp(cmd, "STORE") == 0) {
            if (!arg1 || !rest) {
                reply(fd, "400 BAD REQUEST usage: STORE <key> <value>"); continue;
            }
            if (!valid_key(arg1)) {
                reply(fd, "400 BAD REQUEST invalid key");
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }
            if (!valid_value(rest)) {
                reply(fd, "400 BAD REQUEST value must be 1-%d printable chars",
                      MAX_VALUE);
                pthread_mutex_lock(&stats_lock); bad_requests++;
                pthread_mutex_unlock(&stats_lock);
                continue;
            }
            if (store_put(user, arg1, rest) != 0) {
                reply(fd, "507 FULL the store has no free slots"); continue;
            }
            reply(fd, "200 OK stored %s", arg1);
            continue;
        }

        if (strcmp(cmd, "FETCH") == 0) {
            if (!arg1 || rest || !valid_key(arg1)) {
                reply(fd, "400 BAD REQUEST usage: FETCH <key>"); continue;
            }
            char value[MAX_VALUE + 1];
            /* The lookup is scoped to THIS user, so another user's key of the
               same name is simply not found - isolation by construction. */
            if (store_get(user, arg1, value, sizeof(value)))
                reply(fd, "200 OK %s", value);
            else
                reply(fd, "404 NOT FOUND %s", arg1);
            continue;
        }

        if (strcmp(cmd, "DELETE") == 0) {
            if (!arg1 || rest || !valid_key(arg1)) {
                reply(fd, "400 BAD REQUEST usage: DELETE <key>"); continue;
            }
            reply(fd, store_del(user, arg1) ? "200 OK deleted %s"
                                            : "404 NOT FOUND %s", arg1);
            continue;
        }

        if (strcmp(cmd, "LIST") == 0) {
            char keys[BUF_SIZE / 2];
            int  count = store_list(user, keys, sizeof(keys));
            if (count) reply(fd, "200 OK %d key(s): %s", count, keys);
            else       reply(fd, "200 OK no keys stored");
            continue;
        }

        reply(fd, "400 BAD REQUEST unknown command");
        pthread_mutex_lock(&stats_lock); bad_requests++;
        pthread_mutex_unlock(&stats_lock);
    }

    graceful_close(fd);      /* every exit path, including every error path */

    pthread_mutex_lock(&stats_lock);
    active_connections--;
    pthread_mutex_unlock(&stats_lock);

    printf("[server] conn %d done  (%d command(s))\n", id, served);
    return NULL;
}

int main(int argc, char **argv)
{
    /* Line-buffer the log so entries appear as events happen, even when
       stdout is a pipe or a file (where it would otherwise be fully
       buffered and arrive late and out of order). */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int port        = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    int max_clients = (argc > 2) ? atoi(argv[2]) : DEFAULT_MAX_CLIENTS;

    signal(SIGINT,  handle_sigint);
    signal(SIGPIPE, SIG_IGN);     /* a peer vanishing mid-write must not kill us */

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

    printf("[server] kvstore listening on port %d\n", port);
    printf("[server] thread per client, challenge-response auth, "
           "per-user namespaces\n");
    if (max_clients > 0) printf("[server] will exit after %d connection(s)\n\n",
                                max_clients);
    else                 printf("[server] Ctrl-C to stop\n\n");

    while (keep_running && (max_clients == 0 || total_connections < max_clients)) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&caddr, &clen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept"); break;
        }

        /* Bound the resources one server will commit. Without a cap, enough
           simultaneous connections exhaust memory and descriptors for almost
           no cost to the attacker. */
        pthread_mutex_lock(&stats_lock);
        int active_now = active_connections;
        pthread_mutex_unlock(&stats_lock);
        if (active_now >= MAX_CONCURRENT) {
            const char *busy = "503 BUSY try again later\n";
            send_all(client_fd, busy, strlen(busy));
            graceful_close(client_fd);
            printf("[server] refused a connection (%d already active)\n", active_now);
            continue;
        }

        ClientJob *job = malloc(sizeof(ClientJob));
        if (!job) { close(client_fd); continue; }

        /*
         * Count the connection as active HERE, in the accepting thread, before
         * the handler thread exists.
         *
         * Incrementing inside the handler is a real race: on the last
         * permitted connection this loop exits immediately after
         * pthread_create, and if the new thread has not yet run, the shutdown
         * wait below sees zero active connections, concludes everything is
         * finished, and returns from main - terminating the process and the
         * handler with it, mid-conversation.
         */
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
            pthread_mutex_lock(&stats_lock);      /* undo the optimistic count */
            active_connections--;
            pthread_mutex_unlock(&stats_lock);
            continue;
        }
        pthread_detach(tid);      /* nobody joins it; reclaim it automatically */
    }

    /* Let conversations still in progress finish. The grace period exceeds the
       per-connection receive timeout so a slow client is never cut off before
       the server has finished replying to it. */
    for (int i = 0; i < (RECV_TIMEOUT_SEC + 5) * 10; i++) {
        pthread_mutex_lock(&stats_lock);
        int active = active_connections;
        pthread_mutex_unlock(&stats_lock);
        if (active == 0) break;
        usleep(100000);
    }
    close(listen_fd);

    printf("\n[server] shutting down\n");
    printf("[server] connections    : %d (peak concurrent %d)\n",
           total_connections, peak_concurrent);
    printf("[server] commands served: %d\n", commands_served);
    printf("[server] auth ok/failed : %d / %d\n", auth_ok, auth_fail);
    printf("[server] bad requests   : %d\n", bad_requests);
    return EXIT_SUCCESS;
}
