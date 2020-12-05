#!/bin/sh

test_description='Check munge command-line options'

. "$(dirname "$0")/sharness.sh"

test_expect_success 'munge invalid option' '
    test_must_fail "${MUNGE}" --invalid-option
'

for OPT_HELP in '-h' '--help'; do
    test_expect_success "munge ${OPT_HELP}" '
        "${MUNGE}" "${OPT_HELP}" |
        grep -q "^Usage:"
    '
done

for OPT_LICENSE in '-L' '--license'; do
    test_expect_success "munge ${OPT_LICENSE}" '
        "${MUNGE}" "${OPT_LICENSE}" |
        grep -q "GNU General Public License"
    '
done

for OPT_VERSION in '-V' '--version'; do
    test_expect_success "munge ${OPT_VERSION}" '
        "${MUNGE}" "${OPT_VERSION}" |
        grep -q "^munge-[0-9.]*"
    '
done

test_expect_success 'start munged' '
    munged_setup &&
    munged_create_key &&
    munged_start_daemon
'

for OPT_SOCKET in '-S' '--socket'; do
    test_expect_success "munge ${OPT_SOCKET}" '
        "${MUNGE}" "${OPT_SOCKET}" "${MUNGE_SOCKET}" </dev/null
    '
done

test_expect_success 'munge --socket for missing socket' '
    test_must_fail "${MUNGE}" --socket=missing.socket.$$ </dev/null
'

test_expect_success 'munge --socket for invalid socket (file)' '
    touch invalid.socket.file.$$ &&
    test_must_fail "${MUNGE}" --socket=invalid.socket.file.$$ </dev/null
'

test_expect_success 'munge --socket for invalid socket (directory)' '
    mkdir invalid.socket.dir.$$ &&
    test_must_fail "${MUNGE}" --socket=invalid.socket.dir.$$ </dev/null
'

test_expect_success 'munge reading from stdin' '
    echo -n xyzzy-$$ >in.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" <in.$$ |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
    test_cmp in.$$ out.$$
'

test_expect_success 'munge reading from /dev/null' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" </dev/null |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
    test ! -s out.$$
'

for OPT_NO_INPUT in '-n' '--no-input'; do
    test_expect_success "munge ${OPT_NO_INPUT}" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_NO_INPUT}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --metadata=meta.$$ \
            --output=out.$$ &&
        test "$(awk "/LENGTH:/ { print \$2 }" meta.$$)" -eq 0 &&
        test ! -s out.$$
    '
done

for OPT_STRING in '-s' '--string'; do
    test_expect_success "munge ${OPT_STRING}" '
        local PAYLOAD=xyzzy-$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_STRING}" "${PAYLOAD}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
        test "$(cat out.$$)" = "${PAYLOAD}"
    '
done

for OPT_INPUT in '-i' '--input'; do
    test_expect_success "munge ${OPT_INPUT}" '
        echo -n xyzzy-$$ >in.$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_INPUT}" in.$$ |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
        test_cmp in.$$ out.$$
    '
done

test_expect_success 'munge --input from stdin via "-"' '
    echo -n xyzzy-$$ >in.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --input=- <in.$$ |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
    test_cmp in.$$ out.$$
'

test_expect_success 'munge --input from /dev/null' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --input=/dev/null |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
    test ! -s out.$$
'

test_expect_success 'munge --input from missing file' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" \
            --input=missing.file.$$
'

for OPT_OUTPUT in '-o' '--output'; do
    test_expect_success "munge ${OPT_OUTPUT}" '
        echo -n xyzzy-$$ >in.$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_OUTPUT}" cred.$$ <in.$$ &&
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ --no-output \
                --output=out.$$ &&
        test_cmp in.$$ out.$$
    '
done

test_expect_success 'munge --output to stdout via "-"' '
    echo -n xyzzy-$$ >in.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=- <in.$$ |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
    test_cmp in.$$ out.$$
'

test_expect_success 'munge --output to /dev/null' '
    echo -n xyzzy-$$ >in.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=/dev/null <in.$$ >out.$$ &&
    test ! -s out.$$
'

for OPT_LIST_CIPHERS in '-C' '--list-ciphers'; do
    test_expect_success "munge ${OPT_LIST_CIPHERS}" '
        "${MUNGE}" "${OPT_LIST_CIPHERS}" |
        grep -q "^Cipher types:$"
    '
done

for OPT_CIPHER in '-c' '--cipher'; do
    test_expect_success "munge ${OPT_CIPHER} for default by name" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                "${OPT_CIPHER}" default |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
    '
done

test_expect_success 'munge --cipher for default by number' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher=1 |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
'

test_expect_success 'munge --cipher for none by name' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher=none |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^CIPHER:/ { print \$2 }" >meta.$$ &&
    test "$(cat meta.$$)" = none
'

test_expect_success 'munge --cipher for none by number' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher=0 |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^CIPHER:/ { print \$2 }" >meta.$$ &&
    test "$(cat meta.$$)" = none
'

test_expect_success 'munge --cipher for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --cipher=invalid
'

test_expect_success 'munge --cipher for invalid positive number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher=88
'

test_expect_success 'munge --cipher for invalid negative number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher=-1
'

test_expect_success 'munge --cipher for each cipher by name' '
    local META NAME NUM EXTRA &&
    >fail.$$ &&
    "${MUNGE}" --list-ciphers |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read NUM NAME EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher="${NAME}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^CIPHER:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        if test "${NAME}" = "${META}" || test "${NAME}" = default; then
            test_debug "echo \"Decoded cipher [${NUM}/${NAME}] as [${META}]\""
        else
            echo "Error: munge --cipher=${NAME} failed"
            echo "cipher ${NUM} ${NAME} ${META}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

test_expect_success 'munge --cipher for each cipher by number' '
    local META NAME NUM EXTRA &&
    >fail.$$ &&
    "${MUNGE}" --list-ciphers |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read NUM NAME EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher="${NUM}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^CIPHER:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        if test "${NAME}" = "${META}" || test "${NAME}" = default; then
            test_debug "echo \"Decoded cipher [${NUM}/${NAME}] as [${META}]\""
        else
            echo "Error: munge --cipher=${NUM} failed"
            echo "cipher ${NUM} ${NAME} ${META}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

for OPT_LIST_MACS in '-M' '--list-macs'; do
    test_expect_success "munge ${OPT_LIST_MACS}" '
        "${MUNGE}" "${OPT_LIST_MACS}" |
        grep -q "^MAC types:$"
    '
done

for OPT_MAC in '-m' '--mac'; do
    test_expect_success "munge ${OPT_MAC} for default by name" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input "${OPT_MAC}" default |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
    '
done

test_expect_success 'munge --mac for default by number' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac=1 |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
'

test_expect_success 'munge --mac for none by name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac=none
'

test_expect_success 'munge --mac for none by number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac=0
'

test_expect_success 'munge --mac for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --mac=invalid
'

test_expect_success 'munge --mac for invalid positive number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac=88
'

test_expect_success 'munge --mac for invalid negative number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac=-1
'

test_expect_success 'munge --mac for each mac by name' '
    local META NAME NUM EXTRA &&
    >fail.$$ &&
    "${MUNGE}" --list-macs |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read NUM NAME EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac="${NAME}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^MAC:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        if test "${NAME}" = "${META}" || test "${NAME}" = default; then
            test_debug "echo \"Decoded mac [${NUM}/${NAME}] as [${META}]\""
        else
            echo "Error: munge --mac=${NAME} failed"
            echo "mac ${NUM} ${NAME} ${META}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

test_expect_success 'munge --mac for each mac by number' '
    local META NAME NUM EXTRA &&
    >fail.$$ &&
    "${MUNGE}" --list-macs |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read NUM NAME EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac="${NUM}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^MAC:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        if test "${NAME}" = "${META}" || test "${NAME}" = default; then
            test_debug "echo \"Decoded mac [${NUM}/${NAME}] as [${META}]\""
        else
            echo "Error: munge --mac=${NUM} failed"
            echo "mac ${NUM} ${NAME} ${META}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

for OPT_LIST_ZIPS in '-Z' '--list-zips'; do
    test_expect_success "munge ${OPT_LIST_ZIPS}" '
        "${MUNGE}" "${OPT_LIST_ZIPS}" |
        grep -q "^Compression types:$"
    '
done

# Compression will be disabled if the compressed credential is not smaller than
#   an uncompressed credential.  Consequently, encode a highly-compressible
#   payload when testing --zip to force compression.
##
for OPT_ZIP in '-z' '--zip'; do
    test_expect_success "munge ${OPT_ZIP} for default by name" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                "${OPT_ZIP}" default --string="$(printf %0128d 0)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
    '
done

test_expect_success 'munge --zip for default by number' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip=1 \
            --string="$(printf %0128d 0)" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
'

test_expect_success 'munge --zip for none by name' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip=none \
            --string="$(printf %0128d 0)" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^ZIP:/ { print \$2 }" >meta.$$ &&
    test "$(cat meta.$$)" = none
'

test_expect_success 'munge --zip for none by number' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip=0 \
            --string="$(printf %0128d 0)" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^ZIP:/ { print \$2 }" >meta.$$ &&
    test "$(cat meta.$$)" = none
'

test_expect_success 'munge --zip for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --zip=invalid
'

test_expect_success 'munge --zip for invalid positive number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip=88
'

test_expect_success 'munge --zip for invalid negative number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip=-1
'

test_expect_success 'munge --zip for each zip by name' '
    local META NAME NUM EXTRA &&
    >fail.$$ &&
    "${MUNGE}" --list-zips |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read NUM NAME EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip="${NAME}" \
                --string="$(printf %0128d 0)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^ZIP:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        if test "${NAME}" = "${META}" || test "${NAME}" = default; then
            test_debug "echo \"Decoded zip [${NUM}/${NAME}] as [${META}]\""
        else
            echo "Error: munge --zip=${NAME} failed"
            echo "zip ${NUM} ${NAME} ${META}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

test_expect_success 'munge --zip for each zip by number' '
    local META NAME NUM EXTRA &&
    >fail.$$ &&
    "${MUNGE}" --list-zips |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read NUM NAME EXTRA; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip="${NUM}" \
                --string="$(printf %0128d 0)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^ZIP:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        if test "${NAME}" = "${META}" || test "${NAME}" = default; then
            test_debug "echo \"Decoded zip [${NUM}/${NAME}] as [${META}]\""
        else
            echo "Error: munge --zip=${NUM} failed"
            echo "zip ${NUM} ${NAME} ${META}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

for OPT_RESTRICT_UID in '-u' '--restrict-uid'; do
    test_expect_success "munge ${OPT_RESTRICT_UID} by name" '
        local ID=$(id -u -n) META &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                "${OPT_RESTRICT_UID}" "${ID}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^UID_RESTRICTION:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        test "${ID}" = "${META}" &&
        test_debug "echo \"UID Restriction user [${ID}] matches [${META}]\""
    '
done

test_expect_success 'munge --restrict-uid by number' '
    local ID=$(id -u) META &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --restrict-uid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID_RESTRICTION:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"UID Restriction user [${ID}] matches [${META}]\""
'

test_expect_success 'munge --restrict-uid for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --restrict-uid=invalid$$
'

test_expect_success 'munge --restrict-uid for invalid number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --restrict-uid=-1
'

for OPT_UID in '-U' '--uid'; do
    test_expect_success "munge ${OPT_UID} for effective user by name" '
        local ID=$(id -u -n) META &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input "${OPT_UID}" "${ID}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^UID:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        test "${ID}" = "${META}" &&
        test_debug "echo \"Effective user [${ID}] matches [${META}]\""
    '
done

test_expect_success 'munge --uid for effective user by number' '
    local ID=$(id -u) META &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --uid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"Effective uid [${ID}] matches [${META}]\""
'

test_expect_success SUDO 'munge --uid for root user by name via sudo' '
    local ID=root META &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --uid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID:/ { print \$2 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"sudo user [${ID}] matches [${META}]\""
'

test_expect_success SUDO 'munge --uid for root user by number via sudo' '
    local ID=0 META &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --uid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"sudo uid [${ID}] matches [${META}]\""
'

test_expect_success 'munge --uid for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --uid=invalid$$
'

test_expect_success 'munge --uid for invalid number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --uid=-1
'

for OPT_RESTRICT_GID in '-g' '--restrict-gid'; do
    test_expect_success "munge ${OPT_RESTRICT_GID} by name" '
        local ID=$(id -g -n) META &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                "${OPT_RESTRICT_GID}" "${ID}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^GID_RESTRICTION:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        test "${ID}" = "${META}" &&
        test_debug "echo \"GID Restriction GROUP [${ID}] matches [${META}]\""
    '
done

test_expect_success 'munge --restrict-gid by number' '
    local ID=$(id -g) META &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --restrict-gid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID_RESTRICTION:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"GID Restriction GROUP [${ID}] matches [${META}]\""
'

test_expect_success 'munge --restrict-gid for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --restrict-gid=invalid$$
'

test_expect_success 'munge --restrict-gid for invalid number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --restrict-gid=-1
'

for OPT_GID in '-G' '--gid'; do
    test_expect_success "munge ${OPT_GID} for effective group by name" '
        local ID=$(id -g -n) META &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input "${OPT_GID}" "${ID}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^GID:/ { print \$2 }" >meta.$$ &&
        META=$(cat meta.$$) &&
        test "${ID}" = "${META}" &&
        test_debug "echo \"Effective group [${ID}] matches [${META}]\""
    '
done

test_expect_success 'munge --gid for effective group by number' '
    local ID=$(id -g) META &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --gid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"Effective gid [${ID}] matches [${META}]\""
'

# Since FreeBSD uses the wheel group instead of the root group,
#   query root's group via id.
##
test_expect_success SUDO 'munge --gid for root group by name via sudo' '
    local ID=$(id -g -n root) META &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --gid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID:/ { print \$2 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"sudo group [${ID}] matches [${META}]\""
'

test_expect_success SUDO 'munge --gid for root group by number via sudo' '
    local ID=0 META &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --gid="${ID}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${ID}" = "${META}" &&
    test_debug "echo \"sudo gid [${ID}] matches [${META}]\""
'

test_expect_success 'munge --gid for invalid name' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --gid=invalid$$
'

test_expect_success 'munge --gid for invalid number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --gid=-1
'

for OPT_TTL in '-t' '--ttl'; do
    test_expect_success "munge ${OPT_TTL} for default value" '
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input "${OPT_TTL}" 0 |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
    '
done

test_expect_success 'munge --ttl for maximum value' '
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --ttl=-1 |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output
'

test_expect_success 'munge --ttl for non-default value' '
    local TTL=88 META &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --ttl="${TTL}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^TTL:/ { print \$2 }" >meta.$$ &&
    META=$(cat meta.$$) &&
    test "${TTL}" = "${META}" &&
    test_debug "echo \"TTL [${TTL}] matches [${META}]\""
'

test_expect_success 'munge --ttl for invalid string value' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --ttl=invalid
'

test_expect_success 'munge --ttl for invalid positive number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
            --ttl=4294967296
'

test_expect_success 'munge --ttl for invalid negative number' '
    test_must_fail "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --ttl=-2
'

test_expect_success 'stop munged' '
    munged_stop_daemon
'

test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
