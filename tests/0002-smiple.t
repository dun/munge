#!/bin/sh

test_description="Because nothing is so simple that it can't still go wrong"

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# When testing an expr string regex match for an absolute path, check if the
#   "/" regex should be escaped (i.e., "\/").
# FreeBSD requires the "/" regex in expr to be escaped.
# See "m4/x_ac_with_munge_socket.m4".
#
test_expect_success 'expr string match of absolute path with "/" regex' '
    test_might_fail test "$(expr "/path" : "/")" -eq 1
'
test_expect_success 'expr string match of absolute path with "\/" regex' '
    test "$(expr "/path" : "\/")" -eq 1
'

# Check for a given long option using an expr string regex match.
# Some expr implementations require the option string to be preceded by the
#   "--" parameter to force an end to option-scanning.  But some older
#   implementations don't recognize that syntax.  Since no expr keyword starts
#   with 'X', prepending an 'X' to both strings should be a portable solution.
# FreeBSD requires that a leading argument beginning with a minus sign be
#   considered an option to the program.
#
test_expect_success 'expr string match of long opt' '
    test_might_fail test "$(expr "--exec=foo" : "--exec=")" -eq 7
'
test_expect_success 'expr string match of long opt w/ preceding "--" parm' '
    test_might_fail test "$(expr -- "--exec=foo" : "--exec=")" -eq 7
'
test_expect_success 'expr string match of long opt w/ prepended "X" char' '
    test "$(expr X"--exec=foo" : "X--exec=")" -eq 8
'

# As of GNU grep-3.8, egrep warns that it is obsolescent and should be replaced
#   with "grep -E".
# Check if "grep -E" works for matching extended regular expressions.
#
test_expect_success 'grep extended regex expected failure' '
    echo "hoopy frood" |
    test_must_fail grep "(groovy|hoopy)"
'
test_expect_success 'grep extended regex success' '
    echo "hoopy frood" |
    grep -E "(groovy|hoopy)"
'
test_expect_success 'grep extended regex for end of word expected failure' '
    echo "08.04-oops" |
    test_must_fail grep -E "[0-9.]+( |$)"
'
test_expect_success 'grep extended regex for end of word via end of line' '
    echo "08.04" |
    grep -E "[0-9.]+( |$)"
'
test_expect_success 'grep extended regex for end of word via space char' '
    echo "08.04 (national chocolate-chip cookie day)" |
    grep -E "[0-9.]+( |$)"
'

test_done
