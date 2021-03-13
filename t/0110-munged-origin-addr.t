#!/bin/sh

test_description='Check munged --origin'

. "$(dirname "$0")/sharness.sh"

# Set up the test environment.
##
test_expect_success 'setup' '
    munged_setup &&
    munged_create_key
'

# Check if the command-line option is documented in the help text.
##
test_expect_success 'munged --origin help' '
    "${MUNGED}" --help >out.$$ &&
    grep " --origin=" out.$$
'

# Check for an error when an invalid origin address is specified.
##
test_expect_success 'munged --origin failure' '
    test_must_fail munged_start_daemon --origin=invalid.$$
'

# Check if the error can be overridden when an invalid origin address is
#   specified.
##
test_expect_success 'munged --origin override' '
    munged_start_daemon --origin=invalid.$$ --force &&
    munged_stop_daemon
'

# Check if the origin address is set to the null address when address lookup
#   fails and the error is overridden.
##
test_expect_success 'munged --origin null address' '
    munged_start_daemon --origin=invalid.$$ --force &&
    munged_stop_daemon &&
    egrep "Set origin address to 0\.0\.0\.0\>" "${MUNGE_LOGFILE}"
'

# Check if the origin address is set to the null address in the credential
#   metadata when address lookup fails and the error is overridden.
##
test_expect_success 'munged --origin null address metadata' '
    munged_start_daemon --origin=invalid.$$ --force &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.* 0\.0\.0\.0\>" meta.$$
'

# Check if a warning message is logged to stderr when the origin address is set
#   to the null address.
##
test_expect_success 'munged --origin null address warning' '
    munged_start_daemon --origin=invalid.$$ --force 2>err.$$ &&
    munged_stop_daemon &&
    grep "Warning:.* origin set to null address" err.$$
'

# Check if the origin address can be set by specifying an IP address.
##
test_expect_success 'munged --origin local IP address' '
    rm -f ifname0.$$ &&
    munged_start_daemon --origin=127.0.0.1 &&
    munged_stop_daemon &&
    egrep "Set origin address to 127\.0\.0\.1\>" "${MUNGE_LOGFILE}"
'

# Check if the origin address is set to the appropriate IP address in the
#   credential metadata when specifying an IP address that (probably) matches
#   an address assigned to a local network interface.
##
test_expect_success 'munged --origin local IP address metadata' '
    munged_start_daemon --origin=127.0.0.1 &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.* 127\.0\.0\.1\>" meta.$$
'

# Check the log from the previous test for the network interface name
#   corresponding to the loopback address.
# Set the IFNAME prereq if "ifname0.$$" contains a non-empty string.
##
test_expect_success GETIFADDRS 'munged --origin interface name lookup' '
    local ifname &&
    sed -n -e "s/.*Set origin address.*(\([^)]*\)).*/\1/p" "${MUNGE_LOGFILE}" \
            >ifname0.$$ &&
    ifname=$(cat ifname0.$$) &&
    test_debug "echo \"Loopback network interface name is [${ifname}]\"" &&
    if test "x${ifname}" != x; then test_set_prereq IFNAME; fi
'

# Check if the origin address can be set by specifying the loopback network
#   interface name.
##
test_expect_success IFNAME 'munged --origin interface name' '
    munged_start_daemon --origin="$(cat ifname0.$$)" &&
    munged_stop_daemon &&
    egrep "Set origin address to 127\.0\.0\.1\>" "${MUNGE_LOGFILE}" &&
    sed -n -e "s/.*Set origin address.*(\([^)]*\)).*/\1/p" "${MUNGE_LOGFILE}" \
            >ifname1.$$ &&
    test_cmp ifname0.$$ ifname1.$$
'

# Check if the origin address is set to the appropriate IP address in the
#   credential metadata when specifying the loopback network interface name.
##
test_expect_success IFNAME 'munged --origin interface name metadata' '
    munged_start_daemon --origin="$(cat ifname0.$$)" &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.* 127\.0\.0\.1\>" meta.$$
'

# Check if the origin address can be set to a valid IP address that (probably)
#   does not match an address assigned to a local network interface.
# Note: 192.0.0.0/24 is reserved for IETF Protocol Assignments (rfc6890) so the
#   IP address used here is presumably not likely to be assigned to a local
#   network interface.
# Note: The egrep pattern uses the match-end-of-line operator ($) to ensure an
#   interface name does not follow the IP address.
##
test_expect_success 'munged --origin non-interface IP address' '
    munged_start_daemon --origin=192.0.0.255 &&
    munged_stop_daemon &&
    egrep "Set origin address to 192\.0\.0\.255$" "${MUNGE_LOGFILE}"
'

# Check if the origin address is set to the appropriate IP address in the
#   credential metadata when specifying an IP address that (probably) does not
#   match an address assigned to a local network interface.
##
test_expect_success 'munged --origin non-interface IP address metadata' '
    munged_start_daemon --origin=192.0.0.255 &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.* 192\.0\.0\.255\>" meta.$$
'

# Clean up after a munged process that may not have terminated.
##
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
