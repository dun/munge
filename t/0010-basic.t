#!/bin/sh

test_description='Check basic functionality of MUNGE daemon and clients'

. "$(dirname "$0")/sharness.sh"

test_expect_success 'setup environment' '
    munged_setup_env
'

test_expect_success 'create key' '
    munged_create_key
'

test_expect_success 'check keyfile creation' '
    test -s "${MUNGE_KEYFILE}"
'

test_expect_success 'start munged' '
    munged_start_daemon
'

test_expect_success 'check pidfile creation' '
    test -s "${MUNGE_PIDFILE}"
'

test_expect_success 'check process is running' '
    PID=$(cat "${MUNGE_PIDFILE}") &&
    ps -p "${PID}" -ww | grep munged
'

test_expect_success 'check socket creation' '
    test -S "${MUNGE_SOCKET}"
'

test_expect_success 'check logfile creation' '
    test -s "${MUNGE_LOGFILE}"
'

test_expect_success 'encode credential' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" </dev/null >cred.$$
'

test_expect_success 'examine credential' '
    test "$(expr "$(cat cred.$$)" : "^MUNGE:.*:$")" -gt 0
'

test_expect_success 'decode credential' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

test_expect_success 'replay credential' '
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

test_expect_success 'check logfile for replay' '
    grep "Replayed credential" "${MUNGE_LOGFILE}"
'

test_expect_success 'stop munged' '
    munged_stop_daemon
'

test_expect_success 'check socket removal' '
    test -n "${MUNGE_SOCKET}" &&
    test ! -S "${MUNGE_SOCKET}"
'

test_expect_success 'check process has exited' '
    test -n "${PID}" &&
    ! ps -p "${PID}" >/dev/null
'

test_expect_success 'check pidfile removal' '
    test -n "${MUNGE_PIDFILE}" &&
    test ! -f "${MUNGE_PIDFILE}"
'

test_expect_success 'check seedfile creation' '
    test -s "${MUNGE_SEEDFILE}"
'

test_done
