#!/bin/sh

test_description='Check munged for resource leaks'

: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

if test_have_prereq EXPENSIVE; then :; else
    skip_all='skipping valgrind tests; long test not specified'
    test_done
fi

if test_have_prereq VALGRIND; then :; else
    skip_all='skipping valgrind tests; valgrind not installed'
    test_done
fi

test_expect_success 'start munged under valgrind' '
    munged_setup &&
    munged_create_key &&
    munged_start t-exec="${VALGRIND_CMD}"
'

test_expect_success 'encode credential' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" </dev/null >cred.$$
'

test_expect_success 'decode credential' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

test_expect_success 'replay credential' '
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" <cred.$$ >/dev/null
'

test_expect_success 'stop munged' '
    munged_stop
'

test_expect_success 'check valgrind log for errors in munged' '
    valgrind_check_log
'

test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
