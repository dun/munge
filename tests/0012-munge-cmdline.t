#!/bin/sh

test_description='Check munge command-line options'

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
        grep -q "^munge-[0-9][0-9a-f.]* "
    '
done

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
    echo xyzzy-$$ >in.$$ &&
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
        payload=xyzzy-$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_STRING}" "${payload}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
        test "$(cat out.$$)" = "${payload}"
    '
done

for OPT_INPUT in '-i' '--input'; do
    test_expect_success "munge ${OPT_INPUT}" '
        echo xyzzy-$$ >in.$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_INPUT}" in.$$ |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
        test_cmp in.$$ out.$$
    '
done

test_expect_success 'munge --input from stdin via "-"' '
    echo xyzzy-$$ >in.$$ &&
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
        echo xyzzy-$$ >in.$$ &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" "${OPT_OUTPUT}" cred.$$ <in.$$ &&
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --input=cred.$$ --no-output \
                --output=out.$$ &&
        test_cmp in.$$ out.$$
    '
done

test_expect_success 'munge --output to stdout via "-"' '
    echo xyzzy-$$ >in.$$ &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --output=- <in.$$ |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" --no-output --output=out.$$ &&
    test_cmp in.$$ out.$$
'

test_expect_success 'munge --output to /dev/null' '
    echo xyzzy-$$ >in.$$ &&
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
    >fail.$$ &&
    "${MUNGE}" --list-ciphers |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read num name extra; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher="${name}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^CIPHER:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        if test "${name}" = "${meta}" || test "${name}" = default; then
            test_debug "echo \"Decoded cipher [${num}/${name}] as [${meta}]\""
        else
            echo "Error: munge --cipher=${name} failed"
            echo "cipher ${num} ${name} ${meta}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

test_expect_success 'munge --cipher for each cipher by number' '
    >fail.$$ &&
    "${MUNGE}" --list-ciphers |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read num name extra; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --cipher="${num}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^CIPHER:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        if test "${name}" = "${meta}" || test "${name}" = default; then
            test_debug "echo \"Decoded cipher [${num}/${name}] as [${meta}]\""
        else
            echo "Error: munge --cipher=${num} failed"
            echo "cipher ${num} ${name} ${meta}" >>fail.$$;
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
    >fail.$$ &&
    "${MUNGE}" --list-macs |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read num name extra; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac="${name}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^MAC:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        if test "${name}" = "${meta}" || test "${name}" = default; then
            test_debug "echo \"Decoded mac [${num}/${name}] as [${meta}]\""
        else
            echo "Error: munge --mac=${name} failed"
            echo "mac ${num} ${name} ${meta}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

test_expect_success 'munge --mac for each mac by number' '
    >fail.$$ &&
    "${MUNGE}" --list-macs |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read num name extra; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --mac="${num}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^MAC:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        if test "${name}" = "${meta}" || test "${name}" = default; then
            test_debug "echo \"Decoded mac [${num}/${name}] as [${meta}]\""
        else
            echo "Error: munge --mac=${num} failed"
            echo "mac ${num} ${name} ${meta}" >>fail.$$;
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
#
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
    >fail.$$ &&
    "${MUNGE}" --list-zips |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read num name extra; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip="${name}" \
                --string="$(printf %0128d 0)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^ZIP:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        if test "${name}" = "${meta}" || test "${name}" = default; then
            test_debug "echo \"Decoded zip [${num}/${name}] as [${meta}]\""
        else
            echo "Error: munge --zip=${name} failed"
            echo "zip ${num} ${name} ${meta}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

test_expect_success 'munge --zip for each zip by number' '
    >fail.$$ &&
    "${MUNGE}" --list-zips |
    awk "/([0-9]+)/ { gsub(/[()]/, \"\"); print \$2, \$1 }" |
    while read num name extra; do
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --zip="${num}" \
                --string="$(printf %0128d 0)" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^ZIP:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        if test "${name}" = "${meta}" || test "${name}" = default; then
            test_debug "echo \"Decoded zip [${num}/${name}] as [${meta}]\""
        else
            echo "Error: munge --zip=${num} failed"
            echo "zip ${num} ${name} ${meta}" >>fail.$$;
        fi
    done &&
    test ! -s fail.$$
'

for OPT_RESTRICT_UID in '-u' '--restrict-uid'; do
    test_expect_success "munge ${OPT_RESTRICT_UID} by name" '
        id=$(id -u -n) &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                "${OPT_RESTRICT_UID}" "${id}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^UID_RESTRICTION:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        test "${id}" = "${meta}" &&
        test_debug "echo \"UID Restriction user [${id}] matches [${meta}]\""
    '
done

test_expect_success 'munge --restrict-uid by number' '
    id=$(id -u) &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --restrict-uid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID_RESTRICTION:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"UID Restriction user [${id}] matches [${meta}]\""
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
        id=$(id -u -n) &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input "${OPT_UID}" "${id}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^UID:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        test "${id}" = "${meta}" &&
        test_debug "echo \"Effective user [${id}] matches [${meta}]\""
    '
done

test_expect_success 'munge --uid for effective user by number' '
    id=$(id -u) &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --uid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"Effective uid [${id}] matches [${meta}]\""
'

test_expect_success SUDO 'munge --uid for root user by name via sudo' '
    id=root &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --uid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID:/ { print \$2 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"sudo user [${id}] matches [${meta}]\""
'

test_expect_success SUDO 'munge --uid for root user by number via sudo' '
    id=0 &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --uid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^UID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"sudo uid [${id}] matches [${meta}]\""
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
        id=$(id -g -n) &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input \
                "${OPT_RESTRICT_GID}" "${id}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^GID_RESTRICTION:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        test "${id}" = "${meta}" &&
        test_debug "echo \"GID Restriction GROUP [${id}] matches [${meta}]\""
    '
done

test_expect_success 'munge --restrict-gid by number' '
    id=$(id -g) &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --restrict-gid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID_RESTRICTION:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"GID Restriction GROUP [${id}] matches [${meta}]\""
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
        id=$(id -g -n) &&
        "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input "${OPT_GID}" "${id}" |
        "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
        awk "/^GID:/ { print \$2 }" >meta.$$ &&
        meta=$(cat meta.$$) &&
        test "${id}" = "${meta}" &&
        test_debug "echo \"Effective group [${id}] matches [${meta}]\""
    '
done

test_expect_success 'munge --gid for effective group by number' '
    id=$(id -g) &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --gid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"Effective gid [${id}] matches [${meta}]\""
'

# Since FreeBSD uses the wheel group instead of the root group,
#   query root's group via id.
#
test_expect_success SUDO 'munge --gid for root group by name via sudo' '
    id=$(id -g -n root) &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --gid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID:/ { print \$2 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"sudo group [${id}] matches [${meta}]\""
'

test_expect_success SUDO 'munge --gid for root group by number via sudo' '
    id=0 &&
    sudo LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" "${MUNGE}" \
            --socket="${MUNGE_SOCKET}" --no-input --gid="${id}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^GID:/ { gsub(/[()]/, \"\"); print \$3 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${id}" = "${meta}" &&
    test_debug "echo \"sudo gid [${id}] matches [${meta}]\""
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
    ttl=88 &&
    "${MUNGE}" --socket="${MUNGE_SOCKET}" --no-input --ttl="${ttl}" |
    "${UNMUNGE}" --socket="${MUNGE_SOCKET}" |
    awk "/^TTL:/ { print \$2 }" >meta.$$ &&
    meta=$(cat meta.$$) &&
    test "${ttl}" = "${meta}" &&
    test_debug "echo \"TTL [${ttl}] matches [${meta}]\""
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
    munged_stop
'

test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
