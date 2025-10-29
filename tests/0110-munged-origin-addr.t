#!/bin/sh

test_description='Check munged --origin'

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

# Ensure the daemon can start, or bail out.
#
test_expect_success 'munged startup' '
    munged_start &&
    munged_stop
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

# Check if the command-line option is documented in the help text.
#
test_expect_success 'munged --help output shows --origin' '
    "${MUNGED}" --help >out.$$ &&
    grep " --origin=" out.$$
'

# Check for a fatal error on stderr when the origin cannot be resolved.
#
test_expect_success 'munged failure for nonexistent origin' '
    test_must_fail munged_start --origin="nonexistent.host" 2>err.$$ &&
    grep "Error:.* Failed to resolve origin.*: Host not found" err.$$
'

# Check for a fatal error on stderr when the origin is an invalid IPv4 address.
#
test_expect_success 'munged failure for invalid IPv4 address origin' '
    test_must_fail munged_start --origin="999.999.999.999" 2>err.$$ &&
    grep "Error:.* Failed to resolve origin.*: Host not found" err.$$
'

# Check for a fatal error on stderr when the origin is an IPv6 address.
# Linux returns "Operation not supported"; BSD returns "Host not found".
#
test_expect_success 'munged failure for IPv6 address origin' '
    test_must_fail munged_start --origin="::1" 2>err.$$ &&
    grep -E "Error:.* Failed to resolve origin.* not (found|supported)" err.$$
'

# Check if the error can be overridden when the origin cannot be resolved.
# On resolution failure, the origin should be set to the null address.
#
test_expect_success 'munged failure override for nonexistent origin' '
    NULL_IP="0.0.0.0" &&
    munged_start --origin="nonexistent.host" --force 2>err.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop &&
    test_set_prereq NONEXISTENT
'

# Check for a warning on stderr when the origin cannot be resolved and the
#   error is overridden.
#
test_expect_success NONEXISTENT 'munged warning for nonexistent origin override' '
    grep "Warning:.* Failed to resolve origin" err.$$
'

# Check the logfile to verify the origin is set to the null address when
#   address resolution fails.
#
test_expect_success NONEXISTENT 'munged log msg shows null origin' '
    grep "Set origin address to ${NULL_IP} - null address" "${MUNGE_LOGFILE}"
'

# Check the credential metadata to verify the origin is set to the null address
#   when address resolution fails.
#
test_expect_success NONEXISTENT 'credential metadata shows null origin' '
    grep "^ENCODE_HOST:.* ${NULL_IP}$" meta.$$
'

# Check if a loopback IP address can be specified for the origin.
# Use localhost (127.0.0.1) since it will be bound to the loopback interface,
#   and that interface name can be checked to verify it maps back to localhost.
#
test_expect_success 'munged accepts localhost origin' '
    LOCALHOST_IP="127.0.0.1" &&
    munged_start --origin="${LOCALHOST_IP}" &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop &&
    test_set_prereq LOCALHOST
'

# Check the logfile to verify the origin is set to localhost.
#
test_expect_success LOCALHOST 'munged log msg shows localhost origin' '
    grep "Set origin address to ${LOCALHOST_IP} .*- loopback" \
            "${MUNGE_LOGFILE}"
'

# Check the credential metadata to verify the origin is set to localhost.
#
test_expect_success LOCALHOST 'credential metadata shows localhost origin' '
    grep "^ENCODE_HOST:.* ${LOCALHOST_IP}$" meta.$$
'

# Search the logfile for the loopback network interface name.
# If found, save it in "ifname0.$$" and set the IFNAME prereq.
#
test_expect_success LOCALHOST,GETIFADDRS 'munged log msg shows loopback interface name' '
    sed -n -e "s/.*Set origin address to ${LOCALHOST_IP} (\([^)]*\)).*/\1/p" \
            "${MUNGE_LOGFILE}" >ifname0.$$ &&
    if test "x$(cat ifname0.$$)" != x; then test_set_prereq IFNAME; fi
'

# Check if a network interface name can be specified for the origin.
#
test_expect_success IFNAME 'munged accepts loopback interface name origin' '
    munged_start --origin="$(cat ifname0.$$)" &&
    munged_stop &&
    sed -n -e "s/.*Set origin address to ${LOCALHOST_IP} (\([^)]*\)).*/\1/p" \
            "${MUNGE_LOGFILE}" >ifname1.$$ &&
    test_cmp ifname0.$$ ifname1.$$
'

# Check if a link-local IP address can be specified for the origin.
#
test_expect_success 'munged accepts link-local origin' '
    LINKLOCAL_IP="169.254.13.13" &&
    munged_start --origin="${LINKLOCAL_IP}" &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop &&
    test_set_prereq LINKLOCAL
'

# Check the logfile to verify the origin is set to the link-local address.
#
test_expect_success LINKLOCAL 'munged log msg shows link-local origin' '
    grep "Set origin address to ${LINKLOCAL_IP} .*- link-local" \
            "${MUNGE_LOGFILE}"
'

# Check the credential metadata to verify the origin is set to the link-local
#   address.
#
test_expect_success LINKLOCAL 'credential metadata shows link-local origin' '
    grep "^ENCODE_HOST:.* ${LINKLOCAL_IP}$" meta.$$
'

# Check if an IP address not bound to a local network interface can be
#   specified for the origin.
# RFC 5737 defines the following TEST-NET ranges which should never appear on
#   real interfaces: 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24.
#
test_expect_success 'munged accepts test-net origin' '
    TESTNET_IP="192.0.2.13" &&
    munged_start --origin="${TESTNET_IP}" &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop &&
    test_set_prereq TESTNET
'

# Check the logfile to verify the origin is set to the test-net address.
# Since a test-net address will not be bound to any local interface, check that
#   an interface name does not follow the IP address in the log message by
#   using the match-end-of-line operator ($) in the grep pattern.
#
test_expect_success TESTNET 'munged log msg shows test-net origin' '
    grep "Set origin address to ${TESTNET_IP}$" "${MUNGE_LOGFILE}"
'

# Check the credential metadata to verify the origin is set to the test-net
#   address.
#
test_expect_success TESTNET 'credential metadata shows test-net origin' '
    grep "^ENCODE_HOST:.* ${TESTNET_IP}$" meta.$$
'

test_done
