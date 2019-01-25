#!/bin/sh

test_description='Check custom sharness environment variables'

. "$(dirname "$0")/sharness.sh"

for VAR in MUNGE_BUILD_DIR MUNGE_SOURCE_DIR; do
    test_debug "echo ${VAR}=$(echo \$${VAR})"
    test_expect_success "${VAR} directory exists" "
        test -d "$(echo \"\$\{${VAR}\}\")"
    "
done

test_done
