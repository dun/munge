#!/bin/sh

test_description='Check maximum credential payload'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Ensure cpp is available for processing "munge_defs.h".
#
if ! command -v cpp >/dev/null 2>&1; then
    skip_all='skipping maximum credential payload test; cpp not found'
    test_done
fi

# Get the maximum payload & request sizes, or bail out.
#
get_munge_define()
{
    macro="$1"
    hdr="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h"
    defs=$(grep -E '^#define MUNGE_MAXIMUM_(REQ|PAYLOAD)_LEN' "${hdr}")
    out=$({ echo "${defs}"; echo ${macro}; } | cpp | grep -Ev '^#|^$' |tail -1)
    echo "${out}" | grep -q "^${macro}$" && return 1
    val=$(eval "echo \$((${out}))" 2>/dev/null) || return 1
    test "${val}" -gt 0 || return 1
    echo "${val}"
    return 0
}
MAX_PAYLOAD=$(get_munge_define MUNGE_MAXIMUM_PAYLOAD_LEN) || \
        bail_out "Failed to get MUNGE_MAXIMUM_PAYLOAD_LEN"
MAX_REQUEST=$(get_munge_define MUNGE_MAXIMUM_REQ_LEN) || \
        bail_out "Failed to get MUNGE_MAXIMUM_REQ_LEN"

# Check if bzlib was found.
#
if grep -q '^#define.* HAVE_LIBBZ2 .*1' \
        "${MUNGE_BUILD_DIR}/config.h" >/dev/null 2>&1; then
    test_set_prereq BZLIB
fi

###############################################################################
# Init

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

###############################################################################
# Client Limit Tests

# Test that munge enforces max payload limit even with min encoding overhead.
# Use minimum overhead (no encryption, 128b mac digest, highest compression)
#   to verify the limit applies to the payload, not the encoded credential.
#
test_expect_success BZLIB 'reject encoding max+1 payload (min overhead)' '
    size=$((MAX_PAYLOAD + 1)) &&
    dd if=/dev/zero bs="${size}" count=1 2>/dev/null | \
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=cred.$$ \
            --cipher=none --mac=md5 --zip=bzlib 2>err.$$ &&
    grep "Input size exceeded maximum of ${MAX_PAYLOAD}" err.$$
'

# Test that munge enforces max payload limit even with max encoding overhead.
# Use 128b cipher blocksize, 512b mac digest, and no compression for
#   maximum overhead to ensure the limit is applied at the payload level.
#
test_expect_success 'reject encoding max+1 payload (max overhead)' '
    size=$((MAX_PAYLOAD + 1)) &&
    dd if=/dev/zero bs="${size}" count=1 2>/dev/null | \
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=cred.$$ \
            --cipher=aes256 --mac=sha512 --zip=none 2>err.$$ &&
    grep "Input size exceeded maximum of ${MAX_PAYLOAD}" err.$$
'

# Test that unmunge enforces maximum input (credential) limit.
#
test_expect_success 'reject decoding max+1 input' '
    size=$((MAX_REQUEST + 1)) &&
    dd if=/dev/zero bs="${size}" count=1 2>/dev/null | \
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" \
            >/dev/null 2>err.$$ &&
    grep "Input size exceeded maximum of ${MAX_REQUEST}" err.$$
'

###############################################################################
# Message Transport Limit Tests

# Test that libmunge enforces a maximum size limit on sending requests.
# Decode request message format: 4-byte length + credential + NUL.
# Sending (MAX_REQUEST - 1) credential creates (MAX_REQUEST + 4) request.
# Input NULs are replaced with 'X' since credentials cannot contain NULs.
#
test_expect_success 'reject oversized request message on send' '
    size=$((MAX_REQUEST - 1)) &&
    dd if=/dev/zero bs="${size}" count=1 2>/dev/null | \
    tr "\0" "X" | \
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" \
            >/dev/null 2>err.$$ &&
    grep "Failed to send message:.*exceeded maximum of ${MAX_REQUEST}" err.$$
'

###############################################################################
# Successful Round-Trip Tests

# Test successful encoding at exactly the maximum payload size.
# Use maximum overhead to verify the largest possible credential can
#   still be processed.
#
test_expect_success 'encode max payload (max overhead)' '
    dd if=/dev/zero bs="${MAX_PAYLOAD}" count=1 2>/dev/null | \
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=cred.$$ \
            --cipher=aes256 --mac=sha512 --zip=none
'

# Test successful decoding of a credential with the maximum payload.
# Verify the base64-encoded credential (~33% larger than the payload)
#   won't be rejected.
#
test_expect_success 'decode max payload' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=LENGTH >/dev/null
'

# Verify input payload length matches output payload length.
#
test_expect_success 'verify payload length is preserved' '
    test "${MAX_PAYLOAD}" -eq "$(awk "{print \$2}" meta.$$)"
'

###############################################################################
# libmunge Limit Tests (DEBUG only)

# Test that libmunge enforces the payload limit independently of the client.
# Use MUNGE_TEST_CLIENT_LIMIT_BYPASS to bypass client's input limit in order to
#   test libmunge's enforcement of the limit.
#
test_expect_success DEBUG 'reject encoding max+1 payload via libmunge' '
    size=$((MAX_PAYLOAD + 1)) &&
    export MUNGE_TEST_CLIENT_LIMIT_BYPASS=1 &&
    dd if=/dev/zero bs="${size}" count=1 2>/dev/null | \
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=cred.$$ \
            --cipher=aes256 --mac=sha512 --zip=none 2>err.$$ &&
    unset MUNGE_TEST_CLIENT_LIMIT_BYPASS &&
    grep "Bypassing client input limit" err.$$ &&
    grep "Payload size ${size} exceeded maximum of ${MAX_PAYLOAD}" err.$$
'

# Test that libmunge enforces the credential limit independently of the client.
# Use MUNGE_TEST_CLIENT_LIMIT_BYPASS to bypass client's input limit in order to
#   test libmunge's enforcement of the limit.
# Input NULs are replaced with 'X' since credentials cannot contain NULs.
# Note: libmunge adds +1 to the decode req data_len to account for the NUL.
#
test_expect_success DEBUG 'reject decoding max+1 input via libmunge' '
    size=$((MAX_REQUEST + 1)) &&
    export MUNGE_TEST_CLIENT_LIMIT_BYPASS=1 &&
    dd if=/dev/zero bs="${size}" count=1 2>/dev/null | \
    tr "\0" "X" | \
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" \
            >/dev/null 2>err.$$ &&
    unset MUNGE_TEST_CLIENT_LIMIT_BYPASS &&
    grep "Bypassing client input limit" err.$$ &&
    grep "Credential size $((size + 1)) exceeded maximum of ${MAX_REQUEST}" \
            err.$$
'

###############################################################################
# Fini

# Stop the daemon.
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
