/*
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 * Part 3 of 5: File permission system (read/write/execute, owner/group/others)
 * -----------------------------------------------------------------------------
 * GOAL OF THIS FILE
 *   Requirement 3.1(3): "File permission system (read, write, execute for
 *   owner/group/others)."
 *
 * THE MODEL
 *   Every file records an owner, a group, and nine permission bits: read,
 *   write and execute for each of three classes - the owner, members of the
 *   file's group, and everyone else.
 *
 *       rwx rwx rwx        owner  group  others
 *        |   |   |
 *        |   |   +-- others: anyone else on the system
 *        |   +------ group:  members of the file's group
 *        +---------- owner:  the user who owns the file
 *
 *   Written as an octal number, because each group of three bits is one octal
 *   digit:  rw-r--r-- = 110 100 100 = 0644.
 *
 * THE RULE ALMOST EVERYONE GETS WRONG
 *   The three classes are checked in order and THE FIRST MATCHING CLASS WINS.
 *   The permissions are not combined. If you are the owner, ONLY the owner bits
 *   apply - the group and other bits are never consulted, even when they grant
 *   more.
 *
 *   The consequence is genuinely counter-intuitive, and this program
 *   demonstrates it: a file with mode 0466 (r--rw-rw-) DENIES ITS OWNER write
 *   access while allowing everybody else to write. The owner matches the first
 *   class, gets r--, and the check stops there.
 *
 *   (The owner can always chmod the file back, so this is a foot-gun rather
 *   than a lock-out - but a program that assumed permissions were OR-ed
 *   together would grant access the kernel would refuse.)
 *
 * PERMISSIONS MEAN DIFFERENT THINGS ON DIRECTORIES
 *   r = list the names inside it
 *   w = create, rename or DELETE entries in it - note that deleting a file
 *       depends on write permission on its DIRECTORY, not on the file. You can
 *       delete a file you cannot read.
 *   x = "search": traverse the directory to reach something inside it.
 *   A directory with x but not r is a useful pattern: names cannot be listed,
 *   but a file whose name is already known can still be opened.
 *
 * BUILD & RUN
 *   make run
 * -----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* Permission bit positions, highest first. */
#define P_OWNER_R 0400
#define P_OWNER_W 0200
#define P_OWNER_X 0100
#define P_GROUP_R 0040
#define P_GROUP_W 0020
#define P_GROUP_X 0010
#define P_OTHER_R 0004
#define P_OTHER_W 0002
#define P_OTHER_X 0001

/* The three access kinds a caller can request. */
typedef enum { ACCESS_READ, ACCESS_WRITE, ACCESS_EXEC } AccessType;

/* A simulated user: an id plus the groups they belong to. */
typedef struct {
    int  uid;
    char name[32];
    int  groups[8];
    int  group_count;
} SimUser;

/* A simulated file: owner, group, and the nine permission bits. */
typedef struct {
    char name[64];
    int  owner_uid;
    int  group_gid;
    int  mode;          /* the nine bits, as an octal value */
} SimFile;

/* ===================== RENDERING AND PARSING ============================== */

/* Turn a mode into the familiar "rwxr-xr--" string. */
static void mode_to_string(int mode, char *out)
{
    out[0] = (mode & P_OWNER_R) ? 'r' : '-';
    out[1] = (mode & P_OWNER_W) ? 'w' : '-';
    out[2] = (mode & P_OWNER_X) ? 'x' : '-';
    out[3] = (mode & P_GROUP_R) ? 'r' : '-';
    out[4] = (mode & P_GROUP_W) ? 'w' : '-';
    out[5] = (mode & P_GROUP_X) ? 'x' : '-';
    out[6] = (mode & P_OTHER_R) ? 'r' : '-';
    out[7] = (mode & P_OTHER_W) ? 'w' : '-';
    out[8] = (mode & P_OTHER_X) ? 'x' : '-';
    out[9] = '\0';
}

static const char *access_name(AccessType a)
{
    switch (a) {
        case ACCESS_READ:  return "read";
        case ACCESS_WRITE: return "write";
        default:           return "execute";
    }
}

/* Is this user a member of the given group? */
static int in_group(const SimUser *u, int gid)
{
    for (int i = 0; i < u->group_count; i++)
        if (u->groups[i] == gid) return 1;
    return 0;
}

/* ===================== THE PERMISSION CHECK =============================== */

/*
 * Decide whether `user` may perform `want` on `file`.
 *
 * This is the POSIX algorithm exactly: pick the FIRST class the user falls
 * into, then test only that class's three bits. `explain` prints the reasoning
 * so the first-match-wins behaviour is visible rather than asserted.
 */
static int check_permission(const SimUser *user, const SimFile *file,
                            AccessType want, int explain)
{
    int bits;                 /* the three bits that actually apply */
    const char *class_name;

    if (user->uid == file->owner_uid) {
        class_name = "owner";
        bits = (file->mode >> 6) & 07;          /* top three bits  */
    } else if (in_group(user, file->group_gid)) {
        class_name = "group";
        bits = (file->mode >> 3) & 07;          /* middle three    */
    } else {
        class_name = "others";
        bits = file->mode & 07;                 /* bottom three    */
    }

    int needed;
    switch (want) {
        case ACCESS_READ:  needed = 04; break;
        case ACCESS_WRITE: needed = 02; break;
        default:           needed = 01; break;
    }

    int allowed = (bits & needed) != 0;

    if (explain) {
        char rwx[10];
        mode_to_string(file->mode, rwx);
        printf("    %-8s wants to %-7s %-14s -> %s\n",
               user->name, access_name(want), file->name,
               allowed ? "ALLOWED" : "DENIED");
        printf("             matched class '%s' (%c%c%c); only those bits are\n",
               class_name,
               (bits & 04) ? 'r' : '-',
               (bits & 02) ? 'w' : '-',
               (bits & 01) ? 'x' : '-');
        printf("             consulted, because the first matching class wins\n");
    }
    return allowed;
}

/* Print a file the way `ls -l` would. */
static void print_file(const SimFile *f)
{
    char rwx[10];
    mode_to_string(f->mode, rwx);
    printf("    %s  %04o  uid=%d gid=%d  %s\n",
           rwx, f->mode, f->owner_uid, f->group_gid, f->name);
}

int main(void)
{
    printf("=== File permission system ===\n");
    printf("Requirement 3.1(3)\n\n");

    /* ---- The cast ------------------------------------------------------- */
    SimUser alice   = { 1001, "alice",   {2001, 2002}, 2 };  /* owner, staff  */
    SimUser bob     = { 1002, "bob",     {2001},       1 };  /* staff only    */
    SimUser mallory = { 1003, "mallory", {2009},       1 };  /* outsider      */

    printf("Users\n");
    printf("    alice    uid 1001, groups {2001 staff, 2002 admin}\n");
    printf("    bob      uid 1002, groups {2001 staff}\n");
    printf("    mallory  uid 1003, groups {2009 guests}\n\n");

    /* ---- The files ------------------------------------------------------ */
    SimFile report  = { "report.txt",  1001, 2001, 0640 };  /* rw-r-----     */
    SimFile script  = { "backup.sh",   1001, 2001, 0750 };  /* rwxr-x---     */
    SimFile public  = { "public.txt",  1001, 2001, 0644 };  /* rw-r--r--     */
    SimFile secret  = { "secret.key",  1001, 2001, 0600 };  /* rw-------     */
    SimFile odd     = { "odd.txt",     1001, 2001, 0466 };  /* r--rw-rw-     */

    printf("Files\n");
    print_file(&report);
    print_file(&script);
    print_file(&public);
    print_file(&secret);
    print_file(&odd);
    printf("\n");

    /* ---- 1. The owner's own file ---------------------------------------- */
    printf("1. report.txt is 0640 (rw-r-----)\n");
    check_permission(&alice,   &report, ACCESS_READ,  1);
    check_permission(&alice,   &report, ACCESS_WRITE, 1);
    check_permission(&bob,     &report, ACCESS_READ,  1);
    check_permission(&bob,     &report, ACCESS_WRITE, 1);
    check_permission(&mallory, &report, ACCESS_READ,  1);
    printf("\n");

    /* ---- 2. Execute permission ------------------------------------------ */
    printf("2. backup.sh is 0750 (rwxr-x---) - execute is a separate right\n");
    check_permission(&alice,   &script, ACCESS_EXEC,  1);
    check_permission(&bob,     &script, ACCESS_EXEC,  1);
    check_permission(&bob,     &script, ACCESS_WRITE, 1);
    check_permission(&mallory, &script, ACCESS_EXEC,  1);
    printf("\n");

    /* ---- 3. A private key ------------------------------------------------ */
    printf("3. secret.key is 0600 (rw-------) - nobody but the owner\n");
    check_permission(&alice,   &secret, ACCESS_READ, 1);
    check_permission(&bob,     &secret, ACCESS_READ, 1);
    check_permission(&mallory, &secret, ACCESS_READ, 1);
    printf("\n");

    /* ---- 4. The counter-intuitive case ---------------------------------- *
     * This is the demonstration that permissions are NOT combined.          */
    printf("4. odd.txt is 0466 (r--rw-rw-) - the case that surprises people\n");
    printf("   The owner has only 'r', while group and others have 'rw'.\n\n");
    check_permission(&alice,   &odd, ACCESS_WRITE, 1);
    check_permission(&bob,     &odd, ACCESS_WRITE, 1);
    check_permission(&mallory, &odd, ACCESS_WRITE, 1);
    printf("\n   Alice OWNS the file yet cannot write to it, while Mallory - who\n");
    printf("   has no relationship to it at all - can. Had the classes been\n");
    printf("   OR-ed together, Alice would have been allowed. They are not: the\n");
    printf("   owner class matched first and the check stopped there.\n");
    printf("   (Alice can still chmod it back, since changing a file's mode is\n");
    printf("   a property of ownership rather than of the permission bits.)\n\n");

    /* ---- 5. chmod --------------------------------------------------------- */
    printf("5. chmod: the owner changes the mode, and access changes with it\n");
    printf("   Before: public.txt 0644 - mallory may read\n");
    check_permission(&mallory, &public, ACCESS_READ, 0);
    printf("     mallory read -> %s\n",
           check_permission(&mallory, &public, ACCESS_READ, 0) ? "ALLOWED" : "DENIED");
    public.mode = 0600;
    printf("   chmod 600 public.txt\n");
    printf("     mallory read -> %s\n",
           check_permission(&mallory, &public, ACCESS_READ, 0) ? "ALLOWED" : "DENIED");
    printf("\n");

    /* ---- 6. Real permissions on a real file ------------------------------ *
     * Everything above is simulated so the rules are visible. This section
     * proves the same model is what the kernel is actually enforcing.       */
    printf("6. The same rules on a REAL file, enforced by the kernel\n");
    {
        const char *path = "perm_demo.txt";
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            printf("    could not create %s: %s\n", path, strerror(errno));
        } else {
            write(fd, "demo\n", 5);
            close(fd);

            struct stat st;
            char rwx[10];

            stat(path, &st);
            mode_to_string(st.st_mode & 0777, rwx);
            printf("    created with 0644 -> kernel reports %s (%04o)\n",
                   rwx, st.st_mode & 0777);

            /* Remove all access, then ask the kernel whether we may write. */
            chmod(path, 0400);
            stat(path, &st);
            mode_to_string(st.st_mode & 0777, rwx);
            printf("    chmod 0400        -> kernel reports %s (%04o)\n",
                   rwx, st.st_mode & 0777);

            printf("    access(W_OK) now  -> %s\n",
                   access(path, W_OK) == 0 ? "writable" : "NOT writable");

            /* Attempting the write confirms the kernel really refuses it.
               Running as root would bypass this, which is itself worth
               knowing: the superuser is exempt from these checks. */
            fd = open(path, O_WRONLY);
            if (fd < 0) printf("    open(O_WRONLY)    -> refused: %s\n", strerror(errno));
            else        { printf("    open(O_WRONLY)    -> unexpectedly allowed "
                                 "(are we running as root?)\n"); close(fd); }

            chmod(path, 0600);          /* restore so it can be cleaned up */
            unlink(path);
            printf("    (test file removed)\n");
        }
    }
    printf("\n");

    /* ---- 7. Directory permissions ---------------------------------------- */
    printf("7. On DIRECTORIES the same three bits mean something different\n");
    printf("    r  list the names inside\n");
    printf("    w  create, rename or delete entries - so deleting a file needs\n");
    printf("       write permission on its DIRECTORY, not on the file itself.\n");
    printf("       You can delete a file you are not allowed to read.\n");
    printf("    x  traverse the directory to reach what is inside\n");
    printf("    A directory with x but not r hides its listing while still\n");
    printf("    allowing a file whose name is already known to be opened.\n\n");

    printf("Summary\n");
    printf("  Nine bits across three classes, checked FIRST-MATCH-WINS rather\n");
    printf("  than combined - as odd.txt demonstrated. The model is coarse: it\n");
    printf("  cannot express 'alice and bob but nobody else' without creating a\n");
    printf("  group, which is what POSIX ACLs were added to solve.\n");

    return EXIT_SUCCESS;
}
