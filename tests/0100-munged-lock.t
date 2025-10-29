#!/bin/sh

test_description='Check munged socket lock'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Set up the environment.
# The location of the lockfile is derived from the name of the socket.
# Provide [MUNGE_LOCKFILE] for later checks.
#
test_expect_success 'setup' '
    munged_setup &&
    MUNGE_LOCKFILE="${MUNGE_SOCKET}.lock"
'

# Create a key.
#
test_expect_success 'create key' '
    munged_create_key
'

# Verify the daemon can start, or bail out.
#
test_expect_success 'check munged startup' '
    munged_start &&
    munged_stop
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

# The umask is cleared here to be able to later check if the lockfile has had
#   its permissions set properly.
#
test_expect_success 'start munged with open umask' '
    mask=$(umask) &&
    umask 0 &&
    munged_start &&
    umask "${mask}"
'

# Check if the pidfile has been created, and if it contains the pid of an
#   active munged process.
#
test_expect_success 'check pidfile after munged success' '
    ps -p "$(cat "${MUNGE_PIDFILE}")" -ww | grep munged
'

# Check if the lockfile has been created.
#
test_expect_success 'check lockfile existence' '
    test -e "${MUNGE_LOCKFILE}"
'

# Check if the lockfile is a regular file.
#
test_expect_success 'check lockfile type' '
    test -f "${MUNGE_LOCKFILE}"
'

# Check if the lockfile has the expected permissions for a write-lock.
#
test_expect_success 'check lockfile permissions' '
    ls -ld "${MUNGE_LOCKFILE}" | grep "^--w-------"
'

# Try starting a new munged process using a socket that is already in use.
#   The lockfile should prevent this.
#
test_expect_success 'start munged with in-use socket' '
    test_must_fail munged_start t-keep-process &&
    grep "Error:.* Failed to lock" "${MUNGE_LOGFILE}"
'

# Check if the pidfile still contains the pid of an active munged process.
#   This tests whether the pidfile was corrupted by the preceding attempt
#   to start a new munged process using a socket that was already in use.
#
test_expect_success 'check pidfile after munged failure' '
    ps -p "$(cat "${MUNGE_PIDFILE}")" -ww | grep munged
'

# Stop munged using the --stop option which derives the daemon's pid from
#   the lockfile.
# Check that it responded to SIGTERM indicating it cleaned up before exiting.
#   A successful cleanup is necessary for the subsequent check for lockfile
#   removal.
#
test_expect_success 'stop munged using lockfile-derived pid' '
    munged_stop 2>&1 | grep "Terminated daemon"
'

# Check if the lockfile was removed when munged shut down.
#
test_expect_success 'check lockfile removal' '
    test "x${MUNGE_LOCKFILE}" != x &&
    test ! -f "${MUNGE_LOCKFILE}"
'

# Check if munged will honor a supposed lockfile with read permissions.
#
test_expect_success 'start munged with 0600 bogus lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    touch "${MUNGE_LOCKFILE}" &&
    chmod 0600 "${MUNGE_LOCKFILE}" &&
    test_must_fail munged_start &&
    grep "Error:.* lockfile.* permissions for write by user" "${MUNGE_LOGFILE}"
'

# Check if munged will honor a supposed lockfile with write permissions for
#   group and other.
#
test_expect_success 'start munged with 0222 bogus lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    touch "${MUNGE_LOCKFILE}" &&
    chmod 0222 "${MUNGE_LOCKFILE}" &&
    test_must_fail munged_start &&
    grep "Error:.* lockfile.* permissions for write by user" "${MUNGE_LOGFILE}"
'

# Create a bogus non-empty "lockfile" here to be able to later check if munged
#   has truncated it.
#
test_expect_success 'start munged with inactive non-zero-length lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    echo "$$" > "${MUNGE_LOCKFILE}" &&
    chmod 0200 "${MUNGE_LOCKFILE}" &&
    test -s "${MUNGE_LOCKFILE}" &&
    munged_start
'

# Check if the lockfile gets truncated.
#
test_expect_success 'check for lockfile truncation after successful start' '
    test -f "${MUNGE_LOCKFILE}" &&
    test ! -s "${MUNGE_LOCKFILE}"
'

# Kill munged to prevent cleanup in preparation for a later test to check if
#   munged can recover from a dead socket and lockfile.
#
test_expect_success 'stop munged using sigkill to prevent cleanup' '
    pid=$(cat "${MUNGE_PIDFILE}") &&
    ps -p "${pid}" -ww | grep munged &&
    kill -s KILL "${pid}" &&
    wait_for "! ps -p \"${pid}\""
'

# Check for the leftover socket since munged was prevented from cleaning up.
#
test_expect_success 'check for leftover socket from unclean shutdown' '
    test -S "${MUNGE_SOCKET}"
'

# Check for the leftover lockfile since munged was prevented from cleaning up.
#
test_expect_success 'check for leftover lockfile from unclean shutdown' '
    test -f "${MUNGE_LOCKFILE}"
'

# Check for the leftover pidfile since munged was prevented from cleaning up.
# Remove the pidfile to prevent munged_kill() from logging an error.
#
test_expect_success 'check for leftover pidfile from unclean shutdown' '
    test -f "${MUNGE_PIDFILE}" &&
    rm "${MUNGE_PIDFILE}"
'

# Check if munged can recover from an unclean shutdown.  While the socket and
#   lockfile still exist, the advisory lock will have been automatically
#   dropped when the previous munged died.
#
test_expect_success 'start munged with leftover socket from unclean shutdown' '
    munged_start
'

# Stop the munged that was started for the preceding test.
# Check that it responded to SIGTERM indicating it cleaned up before exiting.
#   A successful cleanup is necessary for the subsequent check for lockfile
#   removal.
#
test_expect_success 'stop munged' '
    munged_stop 2>&1 | grep "Terminated daemon"
'

# Check if the lockfile was removed when munged shut down.
#
test_expect_success 'check lockfile removal again' '
    test "x${MUNGE_LOCKFILE}" != x &&
    test ! -f "${MUNGE_LOCKFILE}"
'

# Check if root can stop a munged process started by a non-privileged user.
#   This tests the case where the lockfile owner (a non-privileged user) is
#   checked against the euid of the process performing the --stop option
#   (root).  If root is unable to stop it, attempt cleanup as the
#   non-privileged user and return a failure status.
#
test_expect_success SUDO 'stop unprivileged munged as root' '
    munged_start &&
    if ! munged_stop t-exec="sudo LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"; then
        munged_stop; false;
    fi
'

test_done
