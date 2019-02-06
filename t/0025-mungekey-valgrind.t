#!/bin/sh

test_description='Check mungekey for resource leaks'

. "$(dirname "$0")/sharness.sh"

if ! test_have_prereq VALGRIND; then
    skip_all='skipping valgrind tests; valgrind not installed'
    test_done
fi

if ! test_have_prereq EXPENSIVE; then
    skip_all='skipping valgrind tests; long test not specified'
    test_done
fi

test_expect_success 'create key under valgrind' '
    munged_setup_env &&
    munged_create_key --exec="${VALGRIND_CMD}"
'

test_expect_success 'check valgrind log for errors in mungekey' '
    valgrind_check_log
'

test_done
