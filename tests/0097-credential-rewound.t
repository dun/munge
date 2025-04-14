#!/bin/sh

test_description='Check decode of a rewound credential'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

if test_have_prereq FAKETIME; then :; else
    skip_all='skipping tests; faketime not installed'
    test_done
fi

# FIXME: Require EXPENSIVE prereq until munged bug with faketime is resolved.
#   The current work-around using sleep could cause false failures.
#
if test_have_prereq EXPENSIVE; then :; else
    skip_all='skipping tests; long test not specified'
    test_done
fi

# Set up the environment.
#
test_expect_success 'setup' '
    munged_setup
'

# Create a key, or bail out.
#
test_expect_success 'create key' '
    munged_create_key t-bail-out-on-error &&
    test -f "${MUNGE_KEYFILE}"
'

# Start the daemon, or bail out.
#
test_expect_success 'start munged' '
    munged_start t-bail-out-on-error
'

# Encode some credentials.  The second one is for testing --ignore-ttl without
#   relying on the behavior of restarting munged to clear its replay cache.
# Provide [TTL], [TTL_SKEW], and [NOW] for later checks.
#
test_expect_success 'encode credential' '
    TTL=300 &&
    TTL_SKEW=5 &&
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

# Start the daemon with a time in the past within the credential's ttl skew.
#   This checks how a credential decode is handled for a clock that is slightly
#   out of sync with the munged that encoded it.
# t-exec does not support using embedded quotation marks to protect whitespace
#   in its embedded args (e.g., "faketime \"301 seconds\"").  To work around
#   this limitation, compute the new time as seconds since the Epoch and
#   specify faketime's timestamp using the @ prefix -- no whitespace required!
# FIXME: The munged parent process hangs during the double-fork while
#   attempting to background itself when called via faketime, so explicitly
#   background munged at the shell.  The subsequent sleep is needed since
#   backgrounding munged at the shell could cause the next sharness test to
#   start executing (and fail) before the daemon has entered its event loop.
#
test_expect_success 'start munged with earlier time within ttl skew' '
    new_time=$((NOW - TTL + TTL_SKEW)) &&
    ( munged_start t-exec="faketime @${new_time}" & ) && sleep 1
'

# Decode a valid negatively-skewed credential -- one with a decode time prior
#   to its encode time by less than the credential's ttl.
#
test_expect_success 'decode negatively-skewed credential' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric <cred.$$ \
        >cred.$$.initial.out &&
    cat cred.$$.initial.out && echo
'

# Stop the daemon.
#
test_expect_success 'stop munged' '
    munged_stop
'

# Start the daemon with a time in the past outside the credential's ttl skew
#   to check how a rewound credential decode is handled.
# Note that restarting munged will clear its replay cache.
# FIXME: The munged parent process hangs so background munged at the shell.
#
test_expect_success 'start munged with earlier time outside ttl skew' '
    new_time=$((NOW - TTL - TTL_SKEW)) &&
    ( munged_start t-exec="faketime @${new_time}" & ) && sleep 1
'

# Decode a rewound credential -- one with a decode time prior to its encode
#   time by more than the credential's ttl.
# Expect EMUNGE_CRED_REWOUND (STATUS=16) since munged believes it is running in
#   the past.
#
test_expect_success 'decode rewound credential' '
    test_expect_code 16 "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric \
        <cred.$$ >cred.$$.rewound.out &&
    cat cred.$$.rewound.out && echo
'

# Verify output of the rewound credential decode matches that of the initial
#   credential decode (with the exception of STATUS and DECODE_TIME).
# This checks that the UID, GID, payload, and metadata can still be retrieved
#   despite the EMUNGE_CRED_REWOUND return status.
#
test_expect_success 'verify rewound credential output' '
    grep -E -v "STATUS:|DECODE_TIME:" <cred.$$.initial.out \
        >cred.$$.initial.match &&
    grep -E -v "STATUS:|DECODE_TIME:" <cred.$$.rewound.out \
        >cred.$$.rewound.match &&
    test_cmp cred.$$.initial.match cred.$$.rewound.match
'

# Decode the same credential again to replay it.
# Expect EMUNGE_CRED_REWOUND (STATUS=16) since replay detection only applies to
#   successfully decoded credentials within their ttl skew.
#
test_expect_success 'replay rewound credential' '
    test_expect_code 16 "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --numeric \
        <cred.$$ >cred.$$.replayed.out &&
    cat cred.$$.replayed.out && echo
'

# Verify output of the replayed credential decode matches that of the rewound
#   credential decode (with the exception of DECODE_TIME since both should have
#   a STATUS of rewound).
#
test_expect_success 'verify replayed rewound credential output' '
    grep -E -v "DECODE_TIME:" <cred.$$.rewound.out >cred.$$.rewound.match &&
    grep -E -v "DECODE_TIME:" <cred.$$.replayed.out >cred.$$.replayed.match &&
    test_cmp cred.$$.rewound.match cred.$$.replayed.match
'

# Decode the same (replayed rewound) credential yet again but now with
#   --ignore-ttl (MUNGE_OPT_IGNORE_TTL).
# Expect success instead of EMUNGE_CRED_REPLAYED since --ignore-ttl will ignore
#   expired, rewound, and replayed errors.
#
test_expect_success 'replay rewound credential with --ignore-ttl' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --ignore-ttl --numeric <cred.$$ \
        >cred.$$.replayed.ignore.ttl.out &&
    cat cred.$$.replayed.ignore.ttl.out && echo
'

# Decode a new rewound credential with --ignore-ttl (MUNGE_OPT_IGNORE_TTL).
#
test_expect_success 'decode new rewound credential with --ignore-ttl' '
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --ignore-ttl --numeric <cred2.$$ \
        >cred.$$.rewound.ignore.ttl.out &&
    cat cred.$$.rewound.ignore.ttl.out && echo
'

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
