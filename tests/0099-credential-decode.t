#!/bin/sh

test_description='Check credential decode to verify crypto portability'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Set up the environment.
#
test_expect_success 'setup' '
    munged_setup
'

# Start the daemon process with the known key, or bail out.
# Force the daemon to run since the key may have the wrong permissions.
#
test_expect_success 'start munged with known key' '
    munged_start --force \
            --key-file="${SHARNESS_TEST_SRCDIR}/0099-credential-decode.key"
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

# Decode a known credential.
# Expect an expired credential (STATUS=15).
#
test_expect_success 'decode known credential' '
    test_expect_code 15 "${UNMUNGE}" --socket="${MUNGE_SOCKET}" \
            --input="${SHARNESS_TEST_SRCDIR}/0099-credential-decode.cred" \
            --numeric >out.$$
'

# Verify the decoded credential matches the expected output.
# Remove the decode time since that is not stored in the known output.
#
test_expect_success 'verify expected output' '
    grep -v DECODE_TIME: <out.$$ >out.post.$$ &&
    test_cmp "${SHARNESS_TEST_SRCDIR}/0099-credential-decode.out" out.post.$$
'

# Stop the daemon process.
#
test_expect_success 'stop munged' '
    munged_stop
'

# Perform housekeeping to clean up afterwards.
#
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
