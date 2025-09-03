#!/bin/sh

test_description='Check mungekey for resource leaks'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

if ! test_have_prereq EXPENSIVE; then
    skip_all='skipping valgrind tests; long test not specified'
    test_done
fi

if ! test_have_prereq VALGRIND; then
    skip_all='skipping valgrind tests; valgrind not installed'
    test_done
fi

# Set up the environment.
#
test_expect_success 'setup' '
    munged_setup
'

# Create a key, or bail out.
#
test_expect_success 'create key under valgrind' '
    munged_create_key t-exec="${VALGRIND_CMD}"
'
test -f "${MUNGE_KEYFILE}" || bail_out "Failed to create key"

test_expect_success 'check valgrind log for errors in mungekey' '
    valgrind_check_log
'

test_done
