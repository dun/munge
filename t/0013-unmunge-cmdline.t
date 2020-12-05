#!/bin/sh

test_description='Check unmunge command-line options'

. "$(dirname "$0")/sharness.sh"

test_expect_success 'unmunge invalid option' '
    test_must_fail "${UNMUNGE}" --invalid-option
'

for OPT_HELP in '-h' '--help'; do
    test_expect_success "unmunge ${OPT_HELP}" '
        "${UNMUNGE}" "${OPT_HELP}" |
        grep -q "^Usage:"
    '
done

for OPT_LICENSE in '-L' '--license'; do
    test_expect_success "unmunge ${OPT_LICENSE}" '
        "${UNMUNGE}" "${OPT_LICENSE}" |
        grep -q "GNU General Public License"
    '
done

for OPT_VERSION in '-V' '--version'; do
    test_expect_success "unmunge ${OPT_VERSION}" '
        "${UNMUNGE}" "${OPT_VERSION}" |
        grep -q "^munge-[0-9.]*"
    '
done

test_expect_success 'start munged' '
    munged_setup &&
    munged_create_key &&
    munged_start_daemon
'

for OPT_SOCKET in '-S' '--socket'; do
    test_expect_success "unmunge ${OPT_SOCKET}" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
        "${UNMUNGE}" "${OPT_SOCKET}" "${MUNGE_SOCKET}" >/dev/null
    '
done

test_expect_success 'unmunge --socket for missing socket' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    test_must_fail "${UNMUNGE}" --socket=missing.socket.$$
'

test_expect_success 'unmunge --socket for invalid socket (file)' '
    touch invalid.socket.file.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    test_must_fail "${UNMUNGE}" --socket=invalid.socket.file.$$
'

test_expect_success 'unmunge --socket for invalid socket (directory)' '
    mkdir invalid.socket.dir.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    test_must_fail "${UNMUNGE}" --socket=invalid.socket.dir.$$
'

test_expect_success 'unmunge reading from /dev/null' '
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" </dev/null
'

for OPT_INPUT in '-i' '--input'; do
    test_expect_success "unmunge ${OPT_INPUT}" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --output=cred.$$ &&
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_INPUT}" cred.$$ \
                >/dev/null
    '
done

test_expect_success 'unmunge --input from stdin via "-"' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=- >/dev/null
'

test_expect_success 'unmunge --input from /dev/null' '
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=/dev/null
'

test_expect_success 'unmunge --input from missing file' '
    test_must_fail "${UNMUNGE}" --socket="${MUNGE_SOCKET}" \
            --input=missing.file.$$
'

for OPT_NO_OUTPUT in '-n' '--no-output'; do
    test_expect_success "unmunge ${OPT_NO_OUTPUT}" '
        local PAYLOAD=xyzzy-$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_NO_OUTPUT}" >out.$$ &&
        test ! -s out.$$
    '
done

for OPT_METADATA in '-m' '--metadata'; do
    test_expect_success "unmunge ${OPT_METADATA}" '
        local PAYLOAD=xyzzy-$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_METADATA}" meta.$$ \
                >out.$$ &&
        grep -q "^STATUS:" meta.$$ &&
        grep -q -v "^${PAYLOAD}" meta.$$ &&
        test "$(cat out.$$)" = "${PAYLOAD}"
    '
done

test_expect_success 'unmunge --metadata to stdout via "-" along with payload' '
    local PAYLOAD=xyzzy-$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --metadata=- >meta.out.$$ &&
    grep -q "^STATUS:" meta.out.$$ &&
    grep -q "^${PAYLOAD}" meta.out.$$
'

test_expect_success 'unmunge --metadata to /dev/null with payload on stdout' '
    local PAYLOAD=xyzzy-$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --metadata=/dev/null >out.$$ &&
    grep -q -v "^STATUS:" out.$$ &&
    test "$(cat out.$$)" = "${PAYLOAD}"
'

for OPT_OUTPUT in '-o' '--output'; do
    test_expect_success "unmunge ${OPT_OUTPUT}" '
        local PAYLOAD=xyzzy-$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_OUTPUT}" out.$$ \
                >meta.$$ &&
        grep -q "^STATUS:" meta.$$ &&
        grep -q -v "^${PAYLOAD}" meta.$$ &&
        test "$(cat out.$$)" = "${PAYLOAD}"
    '
done

test_expect_success 'unmunge --output to stdout via "-" along with metadata' '
    local PAYLOAD=xyzzy-$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --output=- >meta.out.$$ &&
    grep -q "^STATUS:" meta.out.$$ &&
    grep -q "^${PAYLOAD}" meta.out.$$
'

test_expect_success 'unmunge --output to /dev/null with metadata on stdout' '
    local PAYLOAD=xyzzy-$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --string="${PAYLOAD}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --output=/dev/null >meta.$$ &&
    grep -q "^STATUS:" meta.$$ &&
    grep -q -v "${PAYLOAD}" meta.$$
'

for OPT_LIST_KEYS in '-K' '--list-keys'; do
    test_expect_success "unmunge ${OPT_LIST_KEYS}" '
        "${UNMUNGE}" "${OPT_LIST_KEYS}" |
        grep -q "^Metadata keys:$"
    '
done

for OPT_KEYS in '-k' '--keys'; do
    test_expect_success "unmunge ${OPT_KEYS}" '
        local KEY=LENGTH &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_KEYS}" ${KEY} |
        awk "/${KEY}:/ { gsub(/:/, \"\"); print \$1 }" >meta.$$ &&
        test "$(cat meta.$$)" = "${KEY}"
    '
done

test_expect_success 'unmunge --keys for ignoring invalid key' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --keys=invalid
'

test_expect_success 'unmunge --keys for single uppercase key' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --keys=STATUS |
    awk "/STATUS:/ { gsub(/:/, \"\"); print \$1 }" >meta.$$ &&
    test STATUS = "$(cat meta.$$)"
'

test_expect_success 'unmunge --keys for single lowercase key' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --keys=status |
    awk "/STATUS:/ { gsub(/:/, \"\"); print \$1 }" >meta.$$ &&
    test STATUS = "$(cat meta.$$)"
'

for FS in ' ' ',' ';' '.'; do
    test_expect_success "unmunge --keys for multiple keys split by \"${FS}\"" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" \
                --keys="STATUS${FS}UID${FS}GID" |
        awk "/^(STATUS|UID|GID):/ { i++ } END { print i }" >cnt.$$ &&
        test "$(cat cnt.$$)" -eq 3
    '
done

test_expect_success 'unmunge --keys for each key' '
    >fail.$$ &&
    "${UNMUNGE}" --list-keys |
    awk "/^  [A-Z_]+\$/ { print \$1 }" |
    while read KEY EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                --restrict-uid="$(id -u)" --restrict-gid="$(id -g)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --keys="${KEY}" |
        awk "/${KEY}:/ { gsub(/:/, \"\"); print \$1 }" >meta.$$
        if test "$(cat meta.$$)" = "${KEY}"; then
            test_debug "echo \"Tested unmunge --keys=${KEY}\""
        else
            echo "Error: unmunge --keys=${KEY} failed"
            echo "${KEY}" >>fail.$$
        fi
    done &&
    test ! -s fail.$$
'

for OPT_NUMERIC in '-N' '--numeric'; do
    test_expect_success "unmunge ${OPT_NUMERIC}" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                --restrict-uid="$(id -u)" --restrict-gid="$(id -g)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_NUMERIC}" \
                --metadata=meta.$$ &&
        ! grep -q -v "^[A-Z_]*: *[0-9.]*$" meta.$$
    '
done

test_expect_success 'stop munged' '
    munged_stop_daemon
'

test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
