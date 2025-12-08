#!/bin/sh

test_description='Check decode of an expired credential'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

if ! test_have_prereq FAKETIME; then
    skip_all='skipping tests; faketime not installed'
    test_done
fi

# Fails on FreeBSD; cause not yet investigated.
#
if test $(uname -s) != "Linux"; then
    skip_all="skipping tests; $(uname -s) not supported"
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

# Encode some credentials.  The second one is for testing --ignore-ttl without
#   relying on the behavior of restarting munged to clear its replay cache.
# Provide [TTL], [TTL_SKEW], and [NOW] for later checks.
#
test_expect_success 'encode credential' '
    TTL=300 &&
    TTL_SKEW=30 &&
    NOW=$(date +%s) &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="xyzzy-$$" --ttl=${TTL} \
        </dev/null >cred.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="xyzzy-$$" --ttl=${TTL} \
        </dev/null >cred2.$$
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

# Start the daemon with a time in the future within the credential's ttl skew.
#   This checks how a credential decode is handled for a clock that is slightly
#   out of sync with the munged that encoded it.
# t-exec does not support using embedded quotation marks to protect whitespace
#   in its embedded args (e.g., "faketime \"301 seconds\"").  To work around
#   this limitation, compute the new time as seconds since the Epoch and
#   specify faketime's timestamp using the @ prefix -- no whitespace required!
# FIXME: faketime interferes with munged's double-fork daemonization, causing
#   the parent process to hang indefinitely.  Work around this by backgrounding
#   munged at the shell level instead.  Since this bypasses munged's normal
#   startup synchronization (via daemonpipe), we must explicitly wait for
#   munged to be ready before proceeding.
#
test_expect_success 'start munged with later time within ttl skew' '
    new_time=$((NOW + TTL - TTL_SKEW)) &&
    ( munged_start t-exec="faketime @${new_time}" & ) && munged_wait
'

# Decode a valid positively-skewed credential -- one with an encode time prior
#   to its decode time by less than the credential's ttl.
#
test_expect_success 'decode positively-skewed credential' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric <cred.$$ \
        >cred.$$.initial.out &&
    cat cred.$$.initial.out && echo
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

# Start the daemon with a time in the future outside the credential's ttl skew
#   to check how an expired credential decode is handled.
# Note that restarting munged will clear its replay cache.
# FIXME: faketime interferes with munged's double-fork daemonization as above.
#
test_expect_success 'start munged with later time outside ttl skew' '
    new_time=$((NOW + TTL + TTL_SKEW)) &&
    ( munged_start t-exec="faketime @${new_time}" & ) && munged_wait
'

# Decode an expired credential -- one with an encode time prior to its decode
#   time by more than the credential's ttl.
# Expect EMUNGE_CRED_EXPIRED (STATUS=15) since munged believes it is running in
#   the future.
#
test_expect_success 'decode expired credential' '
    test_expect_code 15 "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric \
        <cred.$$ >cred.$$.expired.out &&
    cat cred.$$.expired.out && echo
'

# Verify output of the expired credential decode matches that of the initial
#   credential decode (with the exception of STATUS and DECODE_TIME).
# This checks that the UID, GID, payload, and metadata can still be retrieved
#   despite the EMUNGE_CRED_EXPIRED return status.
#
test_expect_success 'verify expired credential output' '
    grep -E -v "STATUS:|DECODE_TIME:" <cred.$$.initial.out \
        >cred.$$.initial.match &&
    grep -E -v "STATUS:|DECODE_TIME:" <cred.$$.expired.out \
        >cred.$$.expired.match &&
    test_cmp cred.$$.initial.match cred.$$.expired.match
'

# Decode the same credential again to replay it.
# Expect EMUNGE_CRED_EXPIRED (STATUS=15) since replay detection only applies to
#   successfully decoded credentials within their ttl skew.
#
test_expect_success 'replay expired credential' '
    test_expect_code 15 "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric \
        <cred.$$ >cred.$$.replayed.out &&
    cat cred.$$.replayed.out && echo
'

# Verify output of the replayed credential decode matches that of the expired
#   credential decode (with the exception of DECODE_TIME since both should have
#   a STATUS of expired).
#
test_expect_success 'verify replayed expired credential output' '
    grep -E -v "DECODE_TIME:" <cred.$$.expired.out >cred.$$.expired.match &&
    grep -E -v "DECODE_TIME:" <cred.$$.replayed.out >cred.$$.replayed.match &&
    test_cmp cred.$$.expired.match cred.$$.replayed.match
'

# Decode the same (replayed expired) credential yet again but now with
#   --ignore-ttl (MUNGE_OPT_IGNORE_TTL).
# Expect success instead of EMUNGE_CRED_REPLAYED since --ignore-ttl will ignore
#   expired, rewound, and replayed errors.
#
test_expect_success 'replay expired credential with --ignore-ttl' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --ignore-ttl --numeric <cred.$$ \
        >cred.$$.replayed.ignore.ttl.out &&
    cat cred.$$.replayed.ignore.ttl.out && echo
'

# Decode a new expired credential with --ignore-ttl (MUNGE_OPT_IGNORE_TTL).
#
test_expect_success 'decode new expired credential with --ignore-ttl' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --ignore-ttl --numeric <cred2.$$ \
        >cred.$$.expired.ignore.ttl.out &&
    cat cred.$$.expired.ignore.ttl.out && echo
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

test_done
