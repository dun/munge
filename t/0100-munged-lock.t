#!/bin/sh

test_description='Check munged socket lock'

. $(dirname "$0")/sharness.sh

# Setup the environment for starting munged.
# The socket is placed in TMPDIR since NFS can cause problems for the lockfile.
##
test_expect_success 'setup environment' '
    MUNGE_SOCKET="${TMPDIR:-"/tmp"}/munged.sock.$$" &&
    MUNGE_LOCKFILE="${MUNGE_SOCKET}.lock" &&
    MUNGE_KEYFILE="$(pwd)/munged.key.$$" &&
    MUNGE_LOGFILE="$(pwd)/munged.log.$$" &&
    MUNGE_PIDFILE="$(pwd)/munged.pid.$$" &&
    MUNGE_SEEDFILE="$(pwd)/munged.seed.$$" &&
    munged_create_key "${MUNGE_KEYFILE}"
'

# The umask is cleared here to be able to later check if the lockfile has had
#   its permissions set properly.
##
test_expect_success 'start munged with open umask' '
    local MASK=$(umask) &&
    umask 0 &&
    "${MUNGED}" \
        --socket="${MUNGE_SOCKET}" \
        --key-file="${MUNGE_KEYFILE}" \
        --log-file="${MUNGE_LOGFILE}" \
        --pid-file="${MUNGE_PIDFILE}" \
        --seed-file="${MUNGE_SEEDFILE}" &&
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

# Check if the lockfile is an actual file.
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
    test_must_fail "${MUNGED}" \
        --socket="${MUNGE_SOCKET}" \
        --key-file="${MUNGE_KEYFILE}" \
        --log-file="${MUNGE_LOGFILE}" \
        --pid-file="${MUNGE_PIDFILE}" \
        --seed-file="${MUNGE_SEEDFILE}"
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
    "${MUNGED}" --stop --socket="${MUNGE_SOCKET}"
'

# Check if the lockfile was removed when munged shut down.
##
test_expect_success 'check lockfile removal' '
    test ! -f "${MUNGE_LOCKFILE}"
'

# Check if munged will honor a supposed lockfile with read permissions.
##
test_expect_success 'start munged with 0600 bogus lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    touch "${MUNGE_LOCKFILE}" &&
    chmod 0600 "${MUNGE_LOCKFILE}" &&
    test_must_fail "${MUNGED}" \
        --socket="${MUNGE_SOCKET}" \
        --key-file="${MUNGE_KEYFILE}" \
        --log-file="${MUNGE_LOGFILE}" \
        --pid-file="${MUNGE_PIDFILE}" \
        --seed-file="${MUNGE_SEEDFILE}"
'

# Check if munged will honor a supposed lockfile with write permissions for
#   group and other.
##
test_expect_success 'start munged with 0222 bogus lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    touch "${MUNGE_LOCKFILE}" &&
    chmod 0222 "${MUNGE_LOCKFILE}" &&
    test_must_fail "${MUNGED}" \
        --socket="${MUNGE_SOCKET}" \
        --key-file="${MUNGE_KEYFILE}" \
        --log-file="${MUNGE_LOGFILE}" \
        --pid-file="${MUNGE_PIDFILE}" \
        --seed-file="${MUNGE_SEEDFILE}"
'

# Create a bogus non-empty "lockfile" here to be able to later check if munged
#   has truncated it.
##
test_expect_success 'start munged with inactive non-zero lockfile' '
    rm -f "${MUNGE_LOCKFILE}" &&
    echo "$$" > "${MUNGE_LOCKFILE}" &&
    chmod 0200 "${MUNGE_LOCKFILE}" &&
    test -s "${MUNGE_LOCKFILE}" &&
    "${MUNGED}" \
        --socket="${MUNGE_SOCKET}" \
        --key-file="${MUNGE_KEYFILE}" \
        --log-file="${MUNGE_LOGFILE}" \
        --pid-file="${MUNGE_PIDFILE}" \
        --seed-file="${MUNGE_SEEDFILE}"
'

# Check if the lockfile gets truncated.
##
test_expect_success 'check for lockfile truncation after successful start' '
    test ! -s "${MUNGE_LOCKFILE}"
'

# Kill munged to prevent cleanup in preparation for a later test to check if
#   munged can recover from a dead socket and lockfile.
##
test_expect_success 'stop munged via sigkill to prevent cleanup' '
    local PID=$(cat "${MUNGE_PIDFILE}") &&
    ps -p "${PID}" -ww | grep munged &&
    test -S "${MUNGE_SOCKET}" &&
    test -f "${MUNGE_LOCKFILE}" &&
    while kill -s KILL "${PID}" 2>/dev/null; do :; done &&
    test "$(cat "${MUNGE_PIDFILE}")" = "${PID}" &&
    ! ps -p "${PID}"
'

# Check for the expected detritus from the sigkill since munged was prevented
#   from cleaning up.
##
test_expect_success 'check for unclean shutdown' '
    test -S "${MUNGE_SOCKET}" &&
    test -f "${MUNGE_LOCKFILE}" &&
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
        "${MUNGED}" \
            --socket="${MUNGE_SOCKET}" \
            --key-file="${MUNGE_KEYFILE}" \
            --log-file="${MUNGE_LOGFILE}" \
            --pid-file="${MUNGE_PIDFILE}" \
            --seed-file="${MUNGE_SEEDFILE}"
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
    "${MUNGED}" --stop --socket="${MUNGE_SOCKET}"
'

# Check if the lockfile was removed when munged shut down.
##
test_expect_success 'check lockfile removal again' '
    test ! -f "${MUNGE_LOCKFILE}"
'

# Check if root can stop a munged process started by a non-privileged user.
#   This tests the case where the lockfile owner (a non-privileged user)
#   may be checked against the euid (root) of the process performing the
#   --stop option.
##
test_expect_success SUDO 'stop unprivileged munged as root' '
    "${MUNGED}" \
        --socket="${MUNGE_SOCKET}" \
        --key-file="${MUNGE_KEYFILE}" \
        --log-file="${MUNGE_LOGFILE}" \
        --pid-file="${MUNGE_PIDFILE}" \
        --seed-file="${MUNGE_SEEDFILE}" &&
    sudo "${MUNGED}" --stop --socket="${MUNGE_SOCKET}"
'

test_done
