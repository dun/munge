#!/bin/sh

test_description='Check decode of a replayed credential'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

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

# Encode a credential.
#
test_expect_success 'encode credential' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="xyzzy-$$" </dev/null \
        >cred.$$
'

# Decode a credential.
#
test_expect_success 'decode credential' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric <cred.$$ \
        >cred.$$.initial.out &&
    cat cred.$$.initial.out && echo
'

# Decode the same credential again to replay it.
# Expect EMUNGE_CRED_REPLAYED (STATUS=17).
#
test_expect_success 'replay credential' '
    test_expect_code 17 "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric \
        <cred.$$ >cred.$$.replayed.out &&
    cat cred.$$.replayed.out && echo
'

# Verify output of the replayed credential decode matches that of the initial
#   credential decode (with the exception of STATUS and DECODE_TIME).
# This checks that the UID, GID, payload, and metadata can still be retrieved
#   despite the EMUNGE_CRED_REPLAYED return status.
#
test_expect_success 'verify replayed credential output' '
    grep -E -v "STATUS:|DECODE_TIME:" <cred.$$.initial.out \
        >cred.$$.initial.match &&
    grep -E -v "STATUS:|DECODE_TIME:" <cred.$$.replayed.out \
        >cred.$$.replayed.match &&
    test_cmp cred.$$.initial.match cred.$$.replayed.match
'

# Decode the same (replayed unexpired) credential with --ignore-replay
#   (MUNGE_OPT_IGNORE_REPLAY).
#
test_expect_success 'replay credential with --ignore-replay' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --ignore-replay --numeric \
        <cred.$$ >cred.$$.replayed.ignore.replay.out &&
    cat cred.$$.replayed.ignore.replay.out && echo
'

# Decode the same (replayed unexpired) credential with --ignore-ttl
#   (MUNGE_OPT_IGNORE_TTL).
# This should also cause replay errors to be ignored since the replay state is
#   only held until the credential has expired as determined by its ttl.
#
test_expect_success 'replay credential with --ignore-ttl' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --ignore-ttl --numeric \
        <cred.$$ >cred.$$.replayed.ignore.ttl.out &&
    cat cred.$$.replayed.ignore.ttl.out && echo
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

# Start the daemon again in order to check for a persistent replay cache.
#
test_expect_success 'start munged' '
    munged_start
'

# Decode the same credential yet again after having restarted munged to check
#   if the replay cache is restored.
# Since munged does not (yet) support a persistent replay cache, this
#   credential replay should not be detected.
#
test_expect_success 'replay credential after munged restart' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric <cred.$$ \
        >cred.$$.replayed.after.restart.out &&
    cat cred.$$.replayed.after.restart.out && echo
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

test_done
