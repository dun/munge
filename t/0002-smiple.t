#!/bin/sh

test_description="Because nothing is so simple that it can't still go wrong"

. "$(dirname "$0")/sharness.sh"

# Check if the string is a valid absolute pathname (x_ac_with_munge_socket.m4).
##
test_expect_success 'check for absolute pathname with $(expr string : regex)' '
    test "$(expr "/path" : "\/")" -eq 1
'

test_done
