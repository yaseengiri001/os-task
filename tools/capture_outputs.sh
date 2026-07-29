#!/usr/bin/env bash
#
# ST5004CEM - Operating Systems and Security
# Build every task, run every program, and capture the output.
#
# The captured logs are the evidence referenced by the report. Running this
# script is what produces the files in each task's outputs/ directory, so the
# figures in the report can always be regenerated from source rather than being
# screenshots nobody can reproduce.
#
# This is the same script the GitHub Actions workflow runs on an Ubuntu runner
# (.github/workflows/build-and-run.yml), which is how the report's Linux output
# is produced.
#
# Usage:  tools/capture_outputs.sh
# Exits non-zero if any build fails or any program returns a failure status.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAILURES=0
STEP=0

# Ports are offset from a base so repeated local runs do not collide with a
# lingering socket in TIME_WAIT.
PORT_BASE="${PORT_BASE:-9400}"

banner() {
    STEP=$((STEP + 1))
    echo
    echo "======================================================================"
    echo " [$STEP] $*"
    echo "======================================================================"
}

# Record the environment, so a log can always be traced back to the machine
# that produced it. This is what lets the report state where the code ran.
write_env_header() {
    local out="$1"
    {
        echo "# Captured by tools/capture_outputs.sh"
        echo "# Date    : $(date -u '+%Y-%m-%dT%H:%M:%SZ') (UTC)"
        echo "# Host OS : $(uname -srm)"
        echo "# Compiler: $(${CC:-cc} --version 2>/dev/null | head -1)"
        echo "#"
        echo
    } > "$out"
}

# run <output-file> <label> <command...>
run() {
    local out="$1"; shift
    local label="$1"; shift
    mkdir -p "$(dirname "$out")"
    write_env_header "$out"
    echo "--- $label"
    if "$@" >> "$out" 2>&1; then
        echo "    OK   -> $out"
    else
        echo "    FAIL -> $out (exit $?)"
        FAILURES=$((FAILURES + 1))
    fi
}

build() {
    local dir="$1"
    if ! make -C "$dir" >/dev/null 2>&1; then
        echo "    BUILD FAILED: $dir"
        make -C "$dir" 2>&1 | tail -20
        FAILURES=$((FAILURES + 1))
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------- Task 1 ----
banner "Task 1 - Process management and threading"
T1=task1_process_threading
for d in part1_threads part2_synchronization part3_round_robin part4_deadlock \
         task1_combined; do
    build "$T1/$d" || continue
done
run "$T1/outputs/part1_threads.txt"        "part 1: thread creation"      "./$T1/part1_threads/threads_demo"
run "$T1/outputs/part2_synchronization.txt" "part 2: synchronization"     "./$T1/part2_synchronization/sync_demo"
run "$T1/outputs/part3_round_robin.txt"    "part 3: round-robin"          "./$T1/part3_round_robin/round_robin"
run "$T1/outputs/part4_deadlock.txt"       "part 4: deadlock prevention"  "./$T1/part4_deadlock/deadlock"
run "$T1/outputs/task1_combined_all.txt"   "combined: all demos"          "./$T1/task1_combined/task1_combined" all

# ---------------------------------------------------------------- Task 2 ----
banner "Task 2 - Memory management simulation"
T2=task2_memory_management
for d in part1_paging part2_fifo part3_lru part4_statistics task2_combined; do
    build "$T2/$d" || continue
done
run "$T2/outputs/part1_paging.txt"      "part 1: paging (256-byte pages)" "./$T2/part1_paging/paging"
run "$T2/outputs/part1_paging_1024.txt" "part 1: paging (1 KiB pages)"    "./$T2/part1_paging/paging" 1024
run "$T2/outputs/part2_fifo.txt"        "part 2: FIFO + Belady's anomaly" "./$T2/part2_fifo/fifo"
run "$T2/outputs/part3_lru.txt"         "part 3: LRU + stack property"    "./$T2/part3_lru/lru"
run "$T2/outputs/part4_statistics.txt"  "part 4: statistics + comparison" "./$T2/part4_statistics/statistics"
run "$T2/outputs/task2_combined_all.txt" "combined: all demos"            "./$T2/task2_combined/task2_combined" all

# ---------------------------------------------------------------- Task 3 ----
banner "Task 3 - File system operations and security"
T3=task3_filesystem_security
build "$T3/common" || true
run "$T3/outputs/crypto_self_test.txt" "crypto self-test (NIST/RFC vectors)" \
    "./$T3/common/test_vectors"

for d in part1_file_ops part2_authentication part3_permissions \
         part4_encryption part5_audit_log task3_combined; do
    build "$T3/$d" || continue
done

# These programs create working files, so each runs inside its own directory.
run_in() {
    local dir="$1"; local out="$2"; local label="$3"; shift 3
    mkdir -p "$(dirname "$out")"
    write_env_header "$out"
    echo "--- $label"
    if ( cd "$dir" && "$@" ) >> "$out" 2>&1; then
        echo "    OK   -> $out"
    else
        echo "    FAIL -> $out"
        FAILURES=$((FAILURES + 1))
    fi
}

run_in "$T3/part1_file_ops"       "$T3/outputs/part1_file_ops.txt"     "part 1: file operations"  ./file_ops
run_in "$T3/part2_authentication" "$T3/outputs/part2_authentication.txt" "part 2: authentication" ./auth
run_in "$T3/part3_permissions"    "$T3/outputs/part3_permissions.txt"  "part 3: permissions"      ./permissions
run_in "$T3/part4_encryption"     "$T3/outputs/part4_encryption.txt"   "part 4: encryption"       ./encryption
run_in "$T3/part5_audit_log"      "$T3/outputs/part5_audit_log.txt"    "part 5: audit logging"    ./audit_log
run_in "$T3/task3_combined"       "$T3/outputs/task3_combined_demo.txt" "combined: secure file manager" ./task3_combined demo

# ---------------------------------------------------------------- Task 4 ----
banner "Task 4 - Network programming and IPC"
T4=task4_network_ipc
for d in part1_basic_socket part2_concurrent part3_protocol_security \
         task4_combined; do
    build "$T4/$d" || continue
done

# Each network demo starts a server, runs a client against it, then waits.
# The server is given an explicit client count so it terminates on its own.
net_demo() {
    local dir="$1"; local out="$2"; local label="$3"; local port="$4"
    local srv_args="$5"; local cli_args="$6"
    mkdir -p "$(dirname "$out")"
    write_env_header "$out"
    echo "--- $label (port $port)"

    ( cd "$dir" && ./server "$port" $srv_args ) >> "$out" 2>&1 &
    local srv=$!
    sleep 1

    local rc=0
    ( cd "$dir" && ./client 127.0.0.1 "$port" $cli_args ) >> "$out" 2>&1 || rc=$?

    # Give the server a moment to finish and print its summary, then make sure
    # it is gone even if it is still waiting for more clients.
    local waited=0
    while kill -0 "$srv" 2>/dev/null && [ "$waited" -lt 25 ]; do
        sleep 1; waited=$((waited + 1))
    done
    kill "$srv" 2>/dev/null
    wait "$srv" 2>/dev/null

    if [ "$rc" -eq 0 ]; then
        echo "    OK   -> $out"
    else
        echo "    FAIL -> $out (client exit $rc)"
        FAILURES=$((FAILURES + 1))
    fi
}

net_demo "$T4/part1_basic_socket"       "$T4/outputs/part1_basic_socket.txt" \
         "part 1: basic sockets"        "$((PORT_BASE + 1))" "1"  ""
net_demo "$T4/part2_concurrent"         "$T4/outputs/part2_concurrent.txt" \
         "part 2: concurrent clients"   "$((PORT_BASE + 2))" "4"  "4"
net_demo "$T4/part3_protocol_security"  "$T4/outputs/part3_protocol_security.txt" \
         "part 3: protocol + security"  "$((PORT_BASE + 3))" "4"  ""
net_demo "$T4/task4_combined"           "$T4/outputs/task4_combined_demo.txt" \
         "combined: kvstore end to end" "$((PORT_BASE + 4))" "12" "demo"

# ------------------------------------------------------------------ done ----
banner "Summary"
if [ "$FAILURES" -eq 0 ]; then
    echo "All tasks built and ran successfully."
    echo "Captured logs are in each task's outputs/ directory."
    exit 0
fi
echo "$FAILURES step(s) FAILED - see the messages above."
exit 1
