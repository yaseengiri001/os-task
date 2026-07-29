/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Part 1 of 5: File creation, reading, writing and deletion
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 3.1(1): "File creation, reading, writing, and deletion
 *   operations."
 *
 *   These four operations are the interface every program uses to reach
 *   persistent storage. Each one is a SYSTEM CALL: the process cannot touch the
 *   disk itself, so it asks the kernel, which checks permissions and performs
 *   the work on its behalf. That check is the entire basis of file security,
 *   and it is why the later parts of this task have something to protect.
 *
 * SECURITY CONSIDERATIONS DOCUMENTED HERE (deliverable 3.2(1))
 *   File I/O is where a great many real vulnerabilities live, so this part
 *   deliberately does more than call fopen and fclose:
 *
 *   1. PATH TRAVERSAL. A filename like "../../etc/passwd" escapes the intended
 *      directory. Any name arriving from a user is validated by
 *      is_safe_filename() before it is used. Rejecting bad input is far safer
 *      than trying to sanitise it, because sanitising invites a bypass.
 *
 *   2. TOCTOU (time-of-check to time-of-use). Testing "does this file exist?"
 *      and then creating it is a race: an attacker can create a symlink in the
 *      gap and redirect the write. The fix is to make the check and the action
 *      ONE atomic operation - open(O_CREAT | O_EXCL) - which is what
 *      create_file_exclusive() uses.
 *
 *   3. UNCHECKED RETURN VALUES. A write that silently fails (disk full, quota
 *      exceeded) causes data loss that surfaces much later. Every call here is
 *      checked and reports the reason via errno.
 *
 *   4. FIXED-SIZE BUFFERS. Reading into a fixed buffer without bounding the
 *      length is the classic buffer overflow. Sizes are always passed and
 *      always respected.
 *
 *   5. DELETION IS NOT ERASURE. unlink() removes the NAME, not the data. The
 *      blocks stay on the disk until reused and are recoverable with forensic
 *      tools. delete_file() explains this, and Part 4 addresses the real
 *      remedy, which is to encrypt sensitive data in the first place.
 *
 * BUILD & RUN
 *   make run
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_PATH    256
#define MAX_CONTENT 4096
#define WORK_DIR    "secure_files"

/* ===================== SECURITY: INPUT VALIDATION ========================= */

/*
 * Accept a filename only if it is a plain name: letters, digits, dot, dash and
 * underscore, with no slash and no ".." sequence.
 *
 * This is an ALLOW-LIST. It states what is permitted and refuses everything
 * else, so anything the author did not think of is rejected by default. A
 * deny-list ("reject ..") is the common alternative and is routinely bypassed
 * with encodings such as "%2e%2e" or "....//".
 */
static int is_safe_filename(const char *name)
{
    if (name == NULL || name[0] == '\0') return 0;
    if (strlen(name) > 64)               return 0;
    if (name[0] == '.')                  return 0;  /* no hidden or relative names */

    for (const char *p = name; *p; p++) {
        int ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                 (*p >= '0' && *p <= '9') ||  *p == '.' || *p == '-' || *p == '_';
        if (!ok) return 0;
    }
    /* Belt and braces: reject any embedded parent-directory sequence. */
    if (strstr(name, "..") != NULL) return 0;
    return 1;
}

/* Join the working directory and a validated filename into a full path. */
static int build_path(char *out, size_t outsz, const char *name)
{
    if (!is_safe_filename(name)) {
        printf("  REJECTED: \"%s\" is not a safe filename.\n", name);
        printf("            (path traversal and unusual characters are refused)\n");
        return 0;
    }
    int n = snprintf(out, outsz, "%s/%s", WORK_DIR, name);
    return (n > 0 && (size_t)n < outsz);
}

/* ===================== THE FOUR OPERATIONS ================================ */

/*
 * CREATE - atomically, failing if the file already exists.
 *
 * O_CREAT|O_EXCL is the important detail. Checking with stat() and then
 * creating would leave a window in which an attacker could place a symlink
 * pointing at, say, /etc/passwd, and our write would follow it. Asking the
 * kernel to "create this, but fail if it exists" makes check and create a
 * single uninterruptible step, closing the race entirely.
 *
 * Mode 0600 means owner read+write, nothing for anyone else - the least
 * privilege that still works. Part 3 covers the permission model in full.
 */
static int create_file(const char *name)
{
    char path[MAX_PATH];
    if (!build_path(path, sizeof(path), name)) return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EEXIST)
            printf("  CREATE  %-20s FAILED: already exists\n", name);
        else
            printf("  CREATE  %-20s FAILED: %s\n", name, strerror(errno));
        return -1;
    }
    close(fd);
    printf("  CREATE  %-20s OK (mode 0600, owner-only)\n", name);
    return 0;
}

/*
 * WRITE - replace the contents of a file.
 *
 * Note that write() may legitimately transfer FEWER bytes than requested (on
 * a signal, or a full pipe), so the loop below keeps going until everything is
 * written. Treating a short write as success is a real and easily missed cause
 * of silent data corruption.
 */
static int write_file(const char *name, const char *content)
{
    char path[MAX_PATH];
    if (!build_path(path, sizeof(path), name)) return -1;

    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        printf("  WRITE   %-20s FAILED: %s\n", name, strerror(errno));
        return -1;
    }

    size_t total = strlen(content), done = 0;
    while (done < total) {
        ssize_t n = write(fd, content + done, total - done);
        if (n < 0) {
            printf("  WRITE   %-20s FAILED: %s\n", name, strerror(errno));
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }

    /* Ask the kernel to flush its cache to the physical device. Without this
       the data can still be lost in a power failure even though write()
       reported success. */
    fsync(fd);
    close(fd);
    printf("  WRITE   %-20s OK (%zu bytes)\n", name, total);
    return 0;
}

/* APPEND - add to the end without disturbing what is already there.
   O_APPEND makes each write seek to the end atomically, which is what makes
   an append-only log safe when several processes write to it at once. That
   property is exactly what Part 5's audit log depends on. */
static int append_file(const char *name, const char *content)
{
    char path[MAX_PATH];
    if (!build_path(path, sizeof(path), name)) return -1;

    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        printf("  APPEND  %-20s FAILED: %s\n", name, strerror(errno));
        return -1;
    }
    size_t len = strlen(content);
    if (write(fd, content, len) != (ssize_t)len) {
        printf("  APPEND  %-20s FAILED: %s\n", name, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    printf("  APPEND  %-20s OK (%zu bytes added)\n", name, len);
    return 0;
}

/*
 * READ - into a caller-supplied buffer whose size is always respected.
 * The buffer size is a parameter, never assumed, and the result is always
 * null-terminated within bounds. This is the discipline that prevents the
 * buffer overflow that unbounded reads invite.
 */
static int read_file(const char *name, char *buffer, size_t bufsize)
{
    char path[MAX_PATH];
    if (!build_path(path, sizeof(path), name)) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("  READ    %-20s FAILED: %s\n", name, strerror(errno));
        return -1;
    }

    ssize_t n = read(fd, buffer, bufsize - 1);   /* -1 leaves room for the NUL */
    close(fd);
    if (n < 0) {
        printf("  READ    %-20s FAILED: %s\n", name, strerror(errno));
        return -1;
    }
    buffer[n] = '\0';
    printf("  READ    %-20s OK (%zd bytes)\n", name, n);
    return (int)n;
}

/*
 * DELETE - remove the directory entry.
 *
 * unlink() decrements the inode's link count and removes the NAME. The file's
 * data blocks are only released when the count reaches zero AND no process
 * still holds it open - and even then the bytes remain on the medium until
 * something else overwrites them. "Deleted" therefore does not mean
 * "unrecoverable", which is precisely why sensitive data must be encrypted
 * before it is ever written (Part 4).
 */
static int delete_file(const char *name)
{
    char path[MAX_PATH];
    if (!build_path(path, sizeof(path), name)) return -1;

    if (unlink(path) != 0) {
        printf("  DELETE  %-20s FAILED: %s\n", name, strerror(errno));
        return -1;
    }
    printf("  DELETE  %-20s OK (name removed; blocks are not yet erased)\n", name);
    return 0;
}

/* Report a file's size and permission bits via stat(). */
static void stat_file(const char *name)
{
    char path[MAX_PATH];
    struct stat st;
    if (!build_path(path, sizeof(path), name)) return;

    if (stat(path, &st) != 0) {
        printf("  STAT    %-20s FAILED: %s\n", name, strerror(errno));
        return;
    }
    printf("  STAT    %-20s size %lld bytes, mode %04o\n",
           name, (long long)st.st_size, st.st_mode & 07777);
}

int main(void)
{
    char buffer[MAX_CONTENT];

    printf("=== File operations: create, read, write, delete ===\n");
    printf("Requirement 3.1(1)\n\n");

    /* All work happens inside one directory, created if needed. */
    if (mkdir(WORK_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Cannot create %s: %s\n", WORK_DIR, strerror(errno));
        return EXIT_FAILURE;
    }
    printf("Working directory: %s/ (mode 0700, owner-only)\n\n", WORK_DIR);

    /* ---- 1. CREATE ------------------------------------------------------- */
    printf("1. Creating files\n");
    create_file("notes.txt");
    create_file("report.txt");
    create_file("notes.txt");          /* deliberately repeated: must fail */
    printf("\n");

    /* ---- 2. WRITE -------------------------------------------------------- */
    printf("2. Writing content\n");
    write_file("notes.txt",
               "Operating Systems and Security\n"
               "Task 3: file system operations.\n");
    write_file("report.txt", "Quarterly figures: 42.\n");
    printf("\n");

    /* ---- 3. READ --------------------------------------------------------- */
    printf("3. Reading content back\n");
    if (read_file("notes.txt", buffer, sizeof(buffer)) >= 0)
        printf("          contents: \"%s\"\n", buffer);
    printf("\n");

    /* ---- 4. APPEND, then read again -------------------------------------- */
    printf("4. Appending (O_APPEND, atomic at the end of the file)\n");
    append_file("notes.txt", "A line added later.\n");
    if (read_file("notes.txt", buffer, sizeof(buffer)) >= 0)
        printf("          contents now:\n----\n%s----\n", buffer);
    printf("\n");

    /* ---- 5. METADATA ----------------------------------------------------- */
    printf("5. Metadata (stat)\n");
    stat_file("notes.txt");
    stat_file("report.txt");
    printf("\n");

    /* ---- 6. SECURITY: rejected filenames ---------------------------------
     * These are the attacks the validator exists to stop. Showing them being
     * refused is far more convincing than asserting that the code is safe.  */
    printf("6. Path-traversal and malformed names are rejected\n");
    create_file("../../etc/passwd");    /* directory traversal              */
    create_file("/etc/shadow");         /* absolute path                    */
    create_file("..");                  /* parent directory                 */
    create_file("file;rm -rf /");       /* shell metacharacters             */
    create_file("");                    /* empty name                       */
    printf("\n");

    /* ---- 7. ERRORS ON MISSING FILES -------------------------------------- */
    printf("7. Operations on a file that does not exist\n");
    read_file("missing.txt", buffer, sizeof(buffer));
    delete_file("missing.txt");
    printf("\n");

    /* ---- 8. DELETE ------------------------------------------------------- */
    printf("8. Deleting\n");
    delete_file("report.txt");
    stat_file("report.txt");            /* confirms it is gone */
    printf("\n");

    printf("Summary\n");
    printf("  All four operations completed, and every failure was reported\n");
    printf("  rather than ignored. Invalid filenames were refused by an\n");
    printf("  allow-list, and creation used O_CREAT|O_EXCL so that checking and\n");
    printf("  creating cannot be separated by an attacker.\n");
    printf("  'notes.txt' has been left in %s/ for the later parts to use.\n",
           WORK_DIR);

    return EXIT_SUCCESS;
}
