#!/bin/sh

test_description='Check unmunge for resource leaks'

. "$(dirname "$0")/sharness.sh"

if test_have_prereq EXPENSIVE; then :; else
    skip_all='skipping valgrind tests; long test not specified'
    test_done
fi

if test_have_prereq VALGRIND; then :; else
    skip_all='skipping valgrind tests; valgrind not installed'
    test_done
fi

test_expect_success 'start munged' '
    munged_setup &&
    munged_create_key &&
    munged_start_daemon
'

test_expect_success 'encode credential' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" </dev/null >cred.$$
'

test_expect_success 'decode credential under valgrind' '
    ${VALGRIND_CMD} "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

test_expect_success 'stop munged' '
    munged_stop_daemon
'

test_expect_success 'check valgrind log for errors in unmunge' '
    valgrind_check_log
'

test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
