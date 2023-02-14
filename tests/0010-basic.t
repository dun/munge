#!/bin/sh

test_description='Check basic functionality of MUNGE daemon and clients'

: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Set up the environment.
#
test_expect_success 'setup' '
    munged_setup
'

# Create a key for the daemon.
#
test_expect_success 'create key' '
    munged_create_key
'

# Verify the key has been created.
#
test_expect_success 'check keyfile creation' '
    test -s "${MUNGE_KEYFILE}"
'

# Start the daemon.
#
test_expect_success 'start munged' '
    munged_start
'

# Verify the pidfile has been created.
#
test_expect_success 'check pidfile creation' '
    test -s "${MUNGE_PIDFILE}"
'

# Verify the pid in the pidfile matches a running munged process.
# Provide [PID] for later checks.
#
test_expect_success 'check process is running' '
    PID=$(cat "${MUNGE_PIDFILE}") &&
    ps -p "${PID}" -ww | grep munged
'

# Verify the socket has been created.
#
test_expect_success 'check socket creation' '
    test -S "${MUNGE_SOCKET}"
'

# Verify the logfile has been created.
#
test_expect_success 'check logfile creation' '
    test -s "${MUNGE_LOGFILE}"
'

# Encode a credential.
#
test_expect_success 'encode credential' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" </dev/null >cred.$$
'

# Verify the credential string contains the expected prefix and suffix.
#
test_expect_success 'examine credential' '
    test "$(expr X"$(cat cred.$$)" : "XMUNGE:.*:$")" -gt 0
'

# Decode a credential.
#
test_expect_success 'decode credential' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

# Decode the same credential a second time to check if a replay is detected.
#
test_expect_success 'replay credential' '
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

# Check if a message has been logged for the replayed credential.
#
test_expect_success 'check logfile for replay' '
    grep "Replayed credential" "${MUNGE_LOGFILE}"
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

# Verify the daemon is no longer running.
#
test_expect_success 'check process has exited' '
    test "x${PID}" != x &&
    ! ps -p "${PID}" >/dev/null
'

# Verify the socket has been removed.
#
test_expect_success 'check socket removal' '
    test "x${MUNGE_SOCKET}" != x &&
    test ! -S "${MUNGE_SOCKET}"
'

# Verify the pidfile has been removed.
#
test_expect_success 'check pidfile removal' '
    test "x${MUNGE_PIDFILE}" != x &&
    test ! -f "${MUNGE_PIDFILE}"
'

# Verify the seedfile has been created.
#
test_expect_success 'check seedfile creation' '
    test -s "${MUNGE_SEEDFILE}"
'

# Check if the final log message for stopping the daemon has been written out.
#
test_expect_success 'check logfile for final message' '
    grep "Stopping" "${MUNGE_LOGFILE}"
'

# Check the logfile for errors.
#
test_expect_success 'check logfile for errors' '
    ! grep -E -i "(Emergency|Alert|Critical|Error):" "${MUNGE_LOGFILE}"
'

# Perform housekeeping to clean up afterwards.
#
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
