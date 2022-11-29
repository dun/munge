#!/bin/sh

test_description='Check custom sharness environment variables'

. "$(dirname "$0")/sharness.sh"

test_expect_success 'MUNGE_BUILD_DIR directory exists' '
    test_debug "echo MUNGE_BUILD_DIR=${MUNGE_BUILD_DIR}" &&
    test -d "${MUNGE_BUILD_DIR}"
'

test_expect_success 'MUNGE_SOURCE_DIR directory exists' '
    test_debug "echo MUNGE_SOURCE_DIR=${MUNGE_SOURCE_DIR}" &&
    test -d "${MUNGE_SOURCE_DIR}"
'

test_done
