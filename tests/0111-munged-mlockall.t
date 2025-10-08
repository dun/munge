#!/bin/sh

test_description='Check munged --mlockall'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Require EXPENSIVE due to false positives if MIN_MEMLOCK is set too low.
#
if ! test_have_prereq EXPENSIVE; then
    skip_all='skipping tests; long test not specified'
    test_done
fi

# Attempt to raise memlock soft limit to hard limit for testing.
# Portable alternative to 'ulimit -S -l hard' (dash doesn't support 'hard').
#
ulimit -S -l "$(ulimit -H -l)" 2>/dev/null

# Require a minimum memlock limit to reduce false positives.
#
MIN_MEMLOCK=16384
ULIMIT_MEMLOCK=$(ulimit -S -l 2>/dev/null)
if test -z "${ULIMIT_MEMLOCK}"; then
    skip_all='skipping tests; memlock limit not supported'
    test_done
elif test "${ULIMIT_MEMLOCK}" = "unlimited"; then
    : # unlimited is acceptable, continue with tests
elif test "${ULIMIT_MEMLOCK}" -lt "${MIN_MEMLOCK}"; then
    skip_all="skipping tests; memlock limit too low (${ULIMIT_MEMLOCK} KB < ${MIN_MEMLOCK} KB minimum)"
    test_done
fi

# Set up the environment.
#
test_expect_success 'setup' '
    munged_setup
'

# Create a key.
#
test_expect_success 'create key' '
    munged_create_key
'

# Start the daemon with --mlockall, or bail out.
#
test_expect_success 'start munged with --mlockall' '
    munged_start --mlockall
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

# Check the logfile for success.
#
test_expect_success 'check logfile for success' '
    grep -i "Locked pages into memory" "${MUNGE_LOGFILE}"
'

# Check if daemon is still running.
# With --mlockall, failed memory allocations can kill munged after forking.
#
test_expect_success 'check process is running' '
    ps -p "$(cat "${MUNGE_PIDFILE}")" -ww | grep munged
'

# Stop the daemon.
# In debug, dump relevant vm stats before terminating the process.
#
test_expect_success 'stop munged' '
    if test "x${debug}" = xt; then
        pid=$(cat "${MUNGE_PIDFILE}") &&
        grep -E "Vm(Peak|Size|Lck)" "/proc/${pid}/status" 2>/dev/null || :
    fi &&
    munged_stop
'

# Check the logfile for errors.
#
test_expect_success 'check logfile for errors' '
    ! grep -i "Error:" "${MUNGE_LOGFILE}"
'

# Perform housekeeping to clean up afterwards.
#
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
