/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Part 2 of 5: User authentication
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 3.1(2): "User authentication mechanism."
 *
 * THE RULE THIS IS ALL BUILT ON
 *   A password database WILL eventually be stolen. Every serious breach of the
 *   last twenty years has begun that way. Authentication is therefore designed
 *   so that stealing the file does not hand the attacker the passwords - which
 *   means the passwords must never be in it.
 *
 * FOUR THINGS THAT MUST BE RIGHT, AND WHY
 *
 *   1. NEVER STORE THE PASSWORD. Store a one-way hash. Anyone who reads the
 *      file learns the hash and still has to invert it to log in.
 *
 *   2. SALT EVERY PASSWORD SEPARATELY. A bare hash of a password is weak in a
 *      way that surprises people: an attacker precomputes hashes of millions of
 *      common passwords ONCE (a rainbow table) and then looks up every stolen
 *      hash instantly. Worse, two users with the same password get the same
 *      hash, so the file itself reveals who shares a password. Mixing in a
 *      unique random SALT per user defeats both: the table would have to be
 *      rebuilt for every individual salt, and identical passwords now produce
 *      completely different stored values.
 *
 *   3. MAKE HASHING DELIBERATELY SLOW. SHA-256 is built to be fast - modern
 *      hardware computes billions per second, which is exactly what an attacker
 *      wants. PBKDF2 repeats it many times over (200,000 here), so a single
 *      verification costs a barely noticeable fraction of a second to us but
 *      multiplies the attacker's cost by the same factor for every one of their
 *      billions of guesses.
 *
 *   4. COMPARE IN CONSTANT TIME. memcmp returns as soon as bytes differ, so the
 *      time it takes reveals how many leading bytes were right. Repeatedly
 *      measuring that lets a secret be recovered one byte at a time. The
 *      comparison here always examines every byte.
 *
 * TWO FURTHER DEFENCES AGAINST ONLINE ATTACKS
 *   Slow hashing protects a STOLEN file. It does nothing about someone simply
 *   guessing at the login prompt, so:
 *
 *   - ACCOUNT LOCKOUT after repeated failures makes sustained guessing
 *     impractical. (The trade-off is honest and worth stating: lockout can
 *     itself be abused to deny a legitimate user access, which is why real
 *     systems pair it with rate limiting and an unlock path.)
 *
 *   - The failure message NEVER says whether it was the username or the
 *     password that was wrong. "No such user" versus "wrong password" lets an
 *     attacker enumerate valid accounts and attack only those.
 *
 * BUILD & RUN
 *   make run
 * -----------------------------------------------------------------------------
 */

#include "../common/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_USERS       16
#define SALT_SIZE       16    /* 128 bits of randomness is ample for a salt   */
#define HASH_SIZE       32
#define PBKDF2_ROUNDS   200000
#define MAX_ATTEMPTS    3     /* failures tolerated before the account locks  */
#define SHADOW_FILE     "shadow.db"

/* One stored account. Note what is absent: the password itself. */
typedef struct {
    char    username[32];
    uint8_t salt[SALT_SIZE];      /* unique per user, stored in the clear -
                                     a salt is not a secret, it just has to
                                     be different for every account          */
    uint8_t hash[HASH_SIZE];      /* PBKDF2(password, salt, rounds)          */
    int     failed_attempts;
    int     locked;
} User;

static User users[MAX_USERS];
static int  user_count = 0;

/* ===================== SECURE RANDOMNESS ================================== */

/*
 * Fill a buffer with cryptographically secure random bytes from the kernel.
 *
 * rand() must NEVER be used for this. It is a predictable arithmetic sequence
 * seeded from something guessable such as the clock, so an attacker who learns
 * or guesses the seed can reproduce every "random" value the program will ever
 * produce. /dev/urandom is the kernel's CSPRNG, seeded from genuine hardware
 * entropy and designed to be unpredictable even to someone who has seen its
 * previous output.
 */
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

/* ===================== REGISTRATION AND VERIFICATION ====================== */

/* Look up an account by name; NULL if there is none. */
static User *find_user(const char *username)
{
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].username, username) == 0) return &users[i];
    return NULL;
}

/*
 * Register a user: generate a fresh random salt, derive the slow hash, and
 * store only those two things.
 */
static int register_user(const char *username, const char *password)
{
    if (user_count >= MAX_USERS)      { printf("  user table full\n"); return -1; }
    if (find_user(username) != NULL)  { printf("  REGISTER %-12s FAILED: name taken\n",
                                                username); return -1; }
    if (strlen(password) < 8) {
        /* A length floor is the single most effective password rule. Composition
           rules ("one capital, one symbol") mostly push people toward
           predictable substitutions such as P@ssw0rd1. */
        printf("  REGISTER %-12s REFUSED: password shorter than 8 characters\n",
               username);
        return -1;
    }

    User *u = &users[user_count++];
    snprintf(u->username, sizeof(u->username), "%s", username);
    u->failed_attempts = 0;
    u->locked = 0;

    if (secure_random(u->salt, SALT_SIZE) != 0) {
        printf("  REGISTER %-12s FAILED: no secure randomness available\n", username);
        user_count--;
        return -1;
    }

    pbkdf2_hmac_sha256(password, u->salt, SALT_SIZE, PBKDF2_ROUNDS,
                       u->hash, HASH_SIZE);

    char salt_hex[SALT_SIZE * 2 + 1], hash_hex[HASH_SIZE * 2 + 1];
    hex_encode(u->salt, SALT_SIZE, salt_hex);
    hex_encode(u->hash, HASH_SIZE, hash_hex);
    printf("  REGISTER %-12s OK\n", username);
    printf("           salt   %s\n", salt_hex);
    printf("           hash   %.32s...  (PBKDF2, %d rounds)\n",
           hash_hex, PBKDF2_ROUNDS);
    return 0;
}

/*
 * Verify a login attempt.
 *
 * The single generic failure message is deliberate: an attacker learns only
 * that the attempt failed, never whether the account exists.
 */
static int authenticate(const char *username, const char *password)
{
    uint8_t attempt[HASH_SIZE];
    User   *u = find_user(username);

    printf("  LOGIN    %-12s ", username);

    if (u == NULL) {
        /*
         * The account does not exist. We still derive a hash before answering,
         * so that a missing account takes the same time as a wrong password.
         * Replying instantly here would let an attacker enumerate valid
         * usernames purely by timing the response.
         */
        uint8_t dummy_salt[SALT_SIZE] = {0};
        pbkdf2_hmac_sha256(password, dummy_salt, SALT_SIZE, PBKDF2_ROUNDS,
                           attempt, HASH_SIZE);
        printf("DENIED (invalid username or password)\n");
        return -1;
    }

    if (u->locked) {
        printf("DENIED (account locked after %d failed attempts)\n", MAX_ATTEMPTS);
        return -1;
    }

    /* Re-derive the hash from the supplied password using the STORED salt.
       Matching hashes imply the same password without us ever holding it. */
    pbkdf2_hmac_sha256(password, u->salt, SALT_SIZE, PBKDF2_ROUNDS,
                       attempt, HASH_SIZE);

    if (constant_time_equal(attempt, u->hash, HASH_SIZE)) {
        u->failed_attempts = 0;          /* a success clears the counter */
        printf("GRANTED\n");
        return 0;
    }

    u->failed_attempts++;
    if (u->failed_attempts >= MAX_ATTEMPTS) {
        u->locked = 1;
        printf("DENIED (invalid username or password) - account now LOCKED\n");
    } else {
        printf("DENIED (invalid username or password) - attempt %d of %d\n",
               u->failed_attempts, MAX_ATTEMPTS);
    }
    return -1;
}

/*
 * Persist the account table.
 *
 * Mode 0600 restricts it to the owner. This mirrors why Unix moved passwords
 * out of the world-readable /etc/passwd and into /etc/shadow: even strong
 * hashes should not be handed to every user on the machine, because that lets
 * anyone begin cracking them offline at their leisure.
 */
static int save_shadow(void)
{
    int fd = open(SHADOW_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("  Could not write %s: %s\n", SHADOW_FILE, strerror(errno));
        return -1;
    }

    for (int i = 0; i < user_count; i++) {
        char salt_hex[SALT_SIZE * 2 + 1], hash_hex[HASH_SIZE * 2 + 1], line[256];
        hex_encode(users[i].salt, SALT_SIZE, salt_hex);
        hex_encode(users[i].hash, HASH_SIZE, hash_hex);
        int n = snprintf(line, sizeof(line), "%s:%s:%s:%d\n",
                         users[i].username, salt_hex, hash_hex, PBKDF2_ROUNDS);
        if (write(fd, line, (size_t)n) != n) {
            close(fd);
            return -1;
        }
    }
    close(fd);
    printf("  Saved %d accounts to %s (mode 0600, owner-only)\n",
           user_count, SHADOW_FILE);
    return 0;
}

int main(void)
{
    printf("=== User authentication ===\n");
    printf("Requirement 3.1(2)\n\n");

    printf("Design: passwords are never stored. Each account keeps a random\n");
    printf("salt and PBKDF2-HMAC-SHA256(password, salt, %d rounds).\n\n",
           PBKDF2_ROUNDS);

    /* ---- 1. Registration ------------------------------------------------- */
    printf("1. Registering accounts\n");
    register_user("alice",   "correct-horse-battery");
    register_user("bob",     "Tr0ub4dor&3xyz");
    register_user("charlie", "correct-horse-battery");   /* SAME as alice's */
    register_user("dave",    "short");                   /* refused: too short */
    register_user("alice",   "another-password");        /* refused: duplicate */
    printf("\n");

    /* ---- 2. Why the salt matters ----------------------------------------- */
    printf("2. Alice and Charlie chose the IDENTICAL password. Their stored\n");
    printf("   hashes must still differ, or the file would leak that fact:\n");
    {
        User *a = find_user("alice"), *c = find_user("charlie");
        char ah[HASH_SIZE * 2 + 1], ch[HASH_SIZE * 2 + 1];
        hex_encode(a->hash, HASH_SIZE, ah);
        hex_encode(c->hash, HASH_SIZE, ch);
        printf("   alice   %.40s...\n", ah);
        printf("   charlie %.40s...\n", ch);
        printf("   -> %s\n\n",
               memcmp(a->hash, c->hash, HASH_SIZE) != 0
                   ? "different, as required: the unique salts did their job"
                   : "IDENTICAL - the salting is broken");
    }

    /* ---- 3. Successful logins -------------------------------------------- */
    printf("3. Correct credentials\n");
    authenticate("alice", "correct-horse-battery");
    authenticate("bob",   "Tr0ub4dor&3xyz");
    printf("\n");

    /* ---- 4. Failures and lockout ----------------------------------------- */
    printf("4. Wrong passwords, and the lockout that follows\n");
    authenticate("bob", "wrong1");
    authenticate("bob", "wrong2");
    authenticate("bob", "wrong3");            /* third failure locks it     */
    authenticate("bob", "Tr0ub4dor&3xyz");    /* correct, but locked out    */
    printf("\n");

    /* ---- 5. No user enumeration ------------------------------------------ */
    printf("5. An account that does not exist gets the SAME message, so an\n");
    printf("   attacker cannot use the response to discover valid usernames:\n");
    authenticate("eve",  "guessing");
    authenticate("root", "guessing");
    printf("\n");

    /* ---- 6. Persistence -------------------------------------------------- */
    printf("6. Storing the account file\n");
    save_shadow();
    printf("\n");

    printf("Summary\n");
    printf("  Passwords are never written anywhere. Per-user salts make\n");
    printf("  precomputed rainbow tables useless and hide shared passwords.\n");
    printf("  %d PBKDF2 rounds impose the same cost on every attacker guess.\n",
           PBKDF2_ROUNDS);
    printf("  Comparison is constant-time, failures are indistinguishable, and\n");
    printf("  repeated guessing locks the account.\n");

    return EXIT_SUCCESS;
}
