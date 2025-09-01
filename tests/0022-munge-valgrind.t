#!/bin/sh

test_description='Check munge for resource leaks'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
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
test_expect_success 'start munged' '
    munged_start
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

test_expect_success 'encode credential under valgrind' '
    ${VALGRIND_CMD} "${MUNGE}" --socket="${MUNGE_SOCKET}" </dev/null >/dev/null
'

test_expect_success 'stop munged' '
    munged_stop
'

test_expect_success 'check valgrind log for errors in munge' '
    valgrind_check_log
'

test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
