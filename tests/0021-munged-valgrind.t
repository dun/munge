#!/bin/sh

test_description='Check munged for resource leaks'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

if ! test_have_prereq EXPENSIVE; then
    skip_all="skipping tests: --long-tests not specified"
    test_done
fi

if ! test_have_prereq VALGRIND; then
    skip_all="skipping tests: valgrind not installed"
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

# Start the daemon, or bail out.
#
test_expect_success 'start munged under valgrind' '
    munged_start t-exec="${VALGRIND_CMD}"
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

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

test_done
