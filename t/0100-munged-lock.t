#!/bin/sh

test_description='Check munged socket lock'

. "$(dirname "$0")/sharness.sh"

# Setup the environment for testing.
# The location of the lockfile is derived from the name of the socket.
##
test_expect_success 'setup environment' '
    munged_setup_env &&
    munged_create_key &&
    MUNGE_LOCKFILE="${MUNGE_SOCKET}.lock"
'

# The umask is cleared here to be able to later check if the lockfile has had
#   its permissions set properly.
##
test_expect_success 'start munged with open umask' '
    local MASK &&
    MASK=$(umask) &&
    umask 0 &&
    munged_start_daemon &&
    umask "${MASK}"
'

# Check if the pidfile has been created, and if it contains the pid of an
#   active munged process.
##
test_expect_success 'check pidfile after munged success' '
    ps -p "$(cat "${MUNGE_PIDFILE}")" -ww | grep munged
'

# Check if the lockfile has been created.
##
test_expect_success 'check lockfile existence' '
    test -e "${MUNGE_LOCKFILE}"
'

# Check if the lockfile is a regular file.
##
test_expect_success 'check lockfile type' '
    test -f "${MUNGE_LOCKFILE}"
'

# Check if the lockfile has the expected permissions for a write-lock.
##
test_expect_success 'check lockfile permissions' '
    test "$(find ${MUNGE_LOCKFILE} -perm 0200)" = "${MUNGE_LOCKFILE}"
'

# Try starting a new munged process using a socket that is already in use.
#   The lockfile should prevent this.
##
test_expect_success 'start munged with in-use socket' '
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Failed to lock \"${MUNGE_LOCKFILE}\"" "${MUNGE_LOGFILE}"
'

# Check if the pidfile still contains the pid of an active munged process.
#   This tests whether the pidfile was corrupted by the preceding attempt
#   to start a new munged process using a socket that was already in use.
##
test_expect_success 'check pidfile after munged failure' '
    ps -p "$(cat "${MUNGE_PIDFILE}")" -ww | grep munged
'

# Stop munged using the --stop option which derives the daemon's pid from
#   the lockfile.
##
test_expect_success 'stop munged using lockfile-derived pid' '
    munged_stop_daemon
'

# Check if the lockfile was removed when munged shut down.
##
test_expect_success 'check lockfile removal' '
    test -n "${MUNGE_LOCKFILE}" &&
    test ! -f "${MUNGE_LOCKFILE}"
'

# Check if munged will honor a supposed lockfile with read permissions.
##
test_expect_success 'start munged with 0600 bogus lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    touch "${MUNGE_LOCKFILE}" &&
    chmod 0600 "${MUNGE_LOCKFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* \"${MUNGE_LOCKFILE}\" should only be writable by user" \
            "${MUNGE_LOGFILE}"
'

# Check if munged will honor a supposed lockfile with write permissions for
#   group and other.
##
test_expect_success 'start munged with 0222 bogus lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    touch "${MUNGE_LOCKFILE}" &&
    chmod 0222 "${MUNGE_LOCKFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* \"${MUNGE_LOCKFILE}\" should only be writable by user" \
            "${MUNGE_LOGFILE}"
'

# Create a bogus non-empty "lockfile" here to be able to later check if munged
#   has truncated it.
##
test_expect_success 'start munged with inactive non-zero-length lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    echo "$$" > "${MUNGE_LOCKFILE}" &&
    chmod 0200 "${MUNGE_LOCKFILE}" &&
    test -s "${MUNGE_LOCKFILE}" &&
    munged_start_daemon
'

# Check if the lockfile gets truncated.
##
test_expect_success 'check for lockfile truncation after successful start' '
    test -f "${MUNGE_LOCKFILE}" &&
    test ! -s "${MUNGE_LOCKFILE}"
'

# Kill munged to prevent cleanup in preparation for a later test to check if
#   munged can recover from a dead socket and lockfile.
##
test_expect_success 'stop munged via sigkill to prevent cleanup' '
    local PID &&
    PID=$(cat "${MUNGE_PIDFILE}") &&
    ps -p "${PID}" -ww | grep munged &&
    while kill -s KILL "${PID}" 2>/dev/null; do :; done &&
    ! ps -p "${PID}" >/dev/null
'

# Check for the leftover socket since munged was prevented from cleaning up.
##
test_expect_success 'check for leftover socket from unclean shutdown' '
    test -S "${MUNGE_SOCKET}"
'

# Check for the leftover lockfile since munged was prevented from cleaning up.
##
test_expect_success 'check for leftover lockfile from unclean shutdown' '
    test -f "${MUNGE_LOCKFILE}"
'

# Check for the leftover pidfile since munged was prevented from cleaning up.
##
test_expect_success 'check for leftover pidfile from unclean shutdown' '
    test -f "${MUNGE_PIDFILE}"
'

# Check if munged can recover from an unclean shutdown.  While the socket and
#   lockfile still exist, the advisory lock will have been automatically
#   dropped when the previous munged died.
# On Debian 3.1 (Linux 2.4.27-3-386), the advisory lock seems to stay held for
#   a few seconds after the process has terminated.  Therefore, make a few
#   attempts to give the old lock a chance to clear before admitting defeat.
##
test_expect_success 'start munged with leftover socket from unclean shutdown' '
    local i=5 &&
    >fail.$$ &&
    while true; do
        munged_start_daemon
        if test "$?" -eq 0; then
            break
        elif test "$i" -le 1; then
            echo 1 >fail.$$
            break
        else
            i=$((i - 1))
            sleep 1
        fi
    done &&
    test ! -s fail.$$
'

# Stop the munged that was started for the preceding test.
##
test_expect_success 'stop munged' '
    munged_stop_daemon
'

# Check if the lockfile was removed when munged shut down.
##
test_expect_success 'check lockfile removal again' '
    test -n "${MUNGE_LOCKFILE}" &&
    test ! -f "${MUNGE_LOCKFILE}"
'

# Check if root can stop a munged process started by a non-privileged user.
#   This tests the case where the lockfile owner (a non-privileged user)
#   may be checked against the euid (root) of the process performing the
#   --stop option.
# The sudo command cannot call the munged_stop_daemon() shell function so
#   the actual munged command is used here.
##
test_expect_success SUDO 'stop unprivileged munged as root' '
    munged_start_daemon &&
    sudo "${MUNGED}" --stop --socket="${MUNGE_SOCKET}"
'

test_done
