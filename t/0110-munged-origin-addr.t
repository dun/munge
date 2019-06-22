#!/bin/sh

test_description='Check munged --origin'

. "$(dirname "$0")/sharness.sh"

# Setup the test environment.
##
test_expect_success 'setup' '
    munged_setup_env &&
    munged_create_key
'

# Check if the command-line option is documented in the help text.
##
test_expect_success GETIFADDRS 'munged --origin help' '
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

# Check if the origin address is set to the null address when it fails to match
#   an address assigned to a local network interface; this can also happen if
#   getifaddrs() is not found on the system.
##
test_expect_success 'munged --origin null address' '
    munged_start_daemon --origin=invalid.$$ --force &&
    munged_stop_daemon &&
    grep "Set origin address to 0.0.0.0" "${MUNGE_LOGFILE}"
'

# Check if the origin address is set to the null address in the credential
#   metadata.
##
test_expect_success 'munged --origin null address metadata' '
    munged_start_daemon --origin=invalid.$$ --force &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.*\<0\.0\.0\.0\>" meta.$$
'

# Check if the origin address can be set by specifying an IP address.
# Save the interface name to ifname0.$$ for later checks.
##
test_expect_success GETIFADDRS 'munged --origin IP address' '
    rm -f ifname0.$$ &&
    munged_start_daemon --origin=127.0.0.1 &&
    munged_stop_daemon &&
    grep "Set origin address to 127.0.0.1" "${MUNGE_LOGFILE}" &&
    sed -n -e "s/.*Set origin address.*(\([^)]*\)).*/\1/p" \
            "${MUNGE_LOGFILE}" >ifname0.$$
'

# Check if the origin address is set to the appropriate IP address in the
#   credential metadata.
##
test_expect_success GETIFADDRS 'munged --origin IP address metadata' '
    munged_start_daemon --origin=127.0.0.1 &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.*\<127\.0\.0\.1\>" meta.$$
'

# Check if the origin address can be set by specifying an interface name.
##
test_expect_success GETIFADDRS 'munged --origin interface name' '
    test -s ifname0.$$ &&
    munged_start_daemon --origin="$(cat ifname0.$$)" &&
    munged_stop_daemon &&
    grep "Set origin address to 127.0.0.1" "${MUNGE_LOGFILE}" &&
    sed -n -e "s/.*Set origin address.*(\([^)]*\)).*/\1/p" \
            "${MUNGE_LOGFILE}" >ifname1.$$ &&
    test_cmp ifname0.$$ ifname1.$$
'

# Check if the origin address is set to the appropriate IP address in the
#   credential metadata.
##
test_expect_success GETIFADDRS 'munged --origin interface name metadata' '
    test -s ifname0.$$ &&
    munged_start_daemon --origin="$(cat ifname0.$$)" &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ \
            --metadata=meta.$$ --keys=ENCODE_HOST --numeric &&
    munged_stop_daemon &&
    egrep "^ENCODE_HOST:.*\<127\.0\.0\.1\>" meta.$$
'

# Check if the command-line option is documented in the help text if
#   getifaddrs() is not supported.
##
test_expect_success !GETIFADDRS 'munged --origin not supported help omitted' '
    "${MUNGED}" --help >out.$$ &&
    if grep " --origin=" out.$$; then false; fi
'

# Check for a warning if getifaddrs() is not supported and --origin is not
#   specified.
##
test_expect_success !GETIFADDRS 'munged --origin not supported warning' '
    munged_start_daemon 2>err.$$ &&
    munged_stop_daemon &&
    egrep "Warning:.* Failed to match origin .*\<[Nn]ot supported\>" err.$$
'

# Check for an error if getifaddrs() is not supported but --origin is
#   specified.
##
test_expect_success !GETIFADDRS 'munged --origin not supported error' '
    test_must_fail munged_start_daemon --origin=invalid.$$ 2>err.$$ &&
    egrep "Error:.* Failed to match origin .*\<[Nn]ot supported\>" err.$$
'

test_done
