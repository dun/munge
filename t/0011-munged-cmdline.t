#!/bin/sh

test_description='Check munged command-line options'

. "$(dirname "$0")/sharness.sh"

# Set up the test environment.
##
test_expect_success 'setup' '
    munged_setup &&
    munged_create_key
'

test_expect_success 'munged invalid option' '
    test_must_fail "${MUNGED}" --invalid-option
'

for OPT_HELP in '-h' '--help'; do
    test_expect_success "munged ${OPT_HELP}" '
        "${MUNGED}" "${OPT_HELP}" |
        grep -q "^Usage:"
    '
done

for OPT_LICENSE in '-L' '--license'; do
    test_expect_success "munged ${OPT_LICENSE}" '
        "${MUNGED}" "${OPT_LICENSE}" |
        grep -q "GNU General Public License"
    '
done

for OPT_VERSION in '-V' '--version'; do
    test_expect_success "munged ${OPT_VERSION}" '
        "${MUNGED}" "${OPT_VERSION}" |
        grep -q "^munge-[0-9.]*"
    '
done

for OPT_STOP in '-s' '--stop'; do
    test_expect_success "munged ${OPT_STOP}" '
        munged_start_daemon &&
        "${MUNGED}" "${OPT_STOP}" --socket="${MUNGE_SOCKET}"
    '
done

# Check if the stop option properly fails to stop a daemon on a non-existent
#   socket.
##
test_expect_success 'munged --stop for missing socket' '
    test_must_fail "${MUNGED}" --stop --socket=missing.socket.$$
'

for OPT_VERBOSE in '-v' '--verbose'; do
    test_expect_success "munged ${OPT_VERBOSE}" '
        munged_start_daemon &&
        "${MUNGED}" "${OPT_VERBOSE}" --stop --socket="${MUNGE_SOCKET}" 2>&1 |
        egrep -q "(Terminated|Killed) daemon"
    '
done

# Check for a regression of a seedfile being specified by a relative pathname
#   failing to be created at exit.
##
test_expect_success 'munged seedfile creation with relative pathname' '
    local SEEDFILE="seed.$$" &&
    munged_start_daemon --seed-file="${SEEDFILE}" &&
    munged_stop_daemon &&
    test -s "${SEEDFILE}"
'

# Check for a regression of a socket being specified by a relative pathname
#   failing to be removed at exit.
# Set the CWD to the MUNGE_SOCKETDIR (which should be in TMPDIR) in order to
#   prevent the socket pathname from exceeding the maximum length of 108 bytes
#   for a Unix domain socket.  Without this, "make distcheck" failed.
##
test_expect_success 'munged socket cleanup with relative pathname' '
    local SOCKET="socket.$$" &&
    cd "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon --socket="${SOCKET}" &&
    munged_stop_daemon --socket="${SOCKET}" &&
    test ! -S "${SOCKET}"
'

test_expect_failure 'finish writing tests' '
    false
'

# Clean up after a munged process that may not have terminated.
##
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
