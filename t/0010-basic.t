#!/bin/sh

test_description='Check basic functionality of MUNGE daemon and clients'

. "$(dirname "$0")/sharness.sh"

test_expect_success 'setup environment' '
    munged_setup_env
'

test_expect_success 'create key' '
    munged_create_key
'

test_expect_success 'start munged' '
    munged_start_daemon
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

test_expect_success 'stop munged' '
    munged_stop_daemon
'

test_done
