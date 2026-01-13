#!/bin/sh

test_description='Check munged security of keyfile'

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

# Verify the daemon can start, or bail out.
#
test_expect_success 'check munged startup' '
    munged_start &&
    munged_stop
'
test "${MUNGED_START_STATUS}" = 0 || bail_out "Failed to start munged"

# Check for an error when the keyfile is missing.
#
test_expect_success 'keyfile missing failure' '
    local keyfile="${MUNGE_KEYDIR}/munged.key.$$.missing" &&
    test_must_fail munged_start --key-file="${keyfile}" &&
    grep "Error:.* Failed to find keyfile.*: No such file" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is not a regular file.
# Using a directory for the non-regular-file seems the most portable solution.
#
test_expect_success 'keyfile non-regular-file failure' '
    local keyfile="${MUNGE_KEYDIR}/munged.key.$$.non-regular-file" &&
    rm -r -f "${keyfile}" &&
    mkdir "${keyfile}" &&
    test_must_fail munged_start --key-file="${keyfile}" &&
    grep "Error:.* Keyfile.* must be a regular file" "${MUNGE_LOGFILE}" &&
    rmdir "${keyfile}"
'

# Check that the error cannot be overridden when the keyfile is not a regular
#   file.
#
test_expect_success 'keyfile non-regular-file override failure' '
    local keyfile="${MUNGE_KEYDIR}/munged.key.$$.non-regular-file" &&
    rm -r -f "${keyfile}" &&
    mkdir "${keyfile}" &&
    test_must_fail munged_start --key-file="${keyfile}" --force &&
    grep "Error:.* Keyfile.* must be a regular file" "${MUNGE_LOGFILE}" &&
    rmdir "${keyfile}"
'

# Check for an error when the keyfile is a symlink to a regular file.
#
test_expect_success 'keyfile symlink to regular file failure' '
    local keyfile="${MUNGE_KEYFILE}.symlink" &&
    ln -s -f -n "${MUNGE_KEYFILE}" "${keyfile}" &&
    test_must_fail munged_start --key-file="${keyfile}" &&
    grep "Error:.* Keyfile.* a symbolic link" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is a symlink to a
#   regular file.
#
test_expect_success 'keyfile symlink to regular file override' '
    local keyfile="${MUNGE_KEYFILE}.symlink" &&
    ln -s -f -n "${MUNGE_KEYFILE}" "${keyfile}" &&
    munged_start --key-file="${keyfile}" --force &&
    munged_stop &&
    grep "Warning:.* Keyfile.* a symbolic link" "${MUNGE_LOGFILE}"
'

# Check a keyfile owned by the EUID.
#
test_expect_success 'keyfile owned by euid' '
    local key_uid my_euid &&
    key_uid=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$3 }") &&
    my_euid=$(id -u) &&
    test "${key_uid}" = "${my_euid}" &&
    munged_start &&
    munged_stop
'

# Check if the keyfile can be readable by a group that matches the specified
#   trusted group.
#
test_expect_failure 'keyfile readable by trusted group' '
    local gid &&
    gid=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    chmod 0640 "${MUNGE_KEYFILE}" &&
    munged_start --trusted-group="${gid}" &&
    munged_stop
'

# Check for an error when the keyfile is readable by a group that does not
#   match the specified trusted group.
#
test_expect_success 'keyfile readable by untrusted group failure' '
    local gid &&
    gid=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    gid=$((gid + 1)) &&
    chmod 0640 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start --trusted-group="${gid}"
'

# Check if the keyfile can be writable by a group that matches the specified
#   trusted group.
#
test_expect_failure 'keyfile writable by trusted group' '
    local gid &&
    gid=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    chmod 0620 "${MUNGE_KEYFILE}" &&
    munged_start --trusted-group="${gid}" &&
    munged_stop
'

# Check for an error when the keyfile is writable by a group that does not
#   match the specified trusted group.
#
test_expect_success 'keyfile writable by untrusted group failure' '
    local gid &&
    gid=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    gid=$((gid + 1)) &&
    chmod 0620 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start --trusted-group="${gid}"
'

# Check for an error when the keyfile is readable by group.
#
test_expect_success 'keyfile readable by group failure' '
    chmod 0640 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start &&
    grep "Error:.* Keyfile.* readable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is readable by group.
#
test_expect_success 'keyfile readable by group override' '
    chmod 0640 "${MUNGE_KEYFILE}" &&
    munged_start --force &&
    munged_stop &&
    grep "Warning:.* Keyfile.* readable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is writable by group.
#
test_expect_success 'keyfile writable by group failure' '
    chmod 0620 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start &&
    grep "Error:.* Keyfile.* writable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is writable by group.
#
test_expect_success 'keyfile writable by group override' '
    chmod 0620 "${MUNGE_KEYFILE}" &&
    munged_start --force &&
    munged_stop &&
    grep "Warning:.* Keyfile.* writable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is readable by other.
#
test_expect_success 'keyfile readable by other failure' '
    chmod 0604 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start &&
    grep "Error:.* Keyfile.* readable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is readable by other.
#
test_expect_success 'keyfile readable by other override' '
    chmod 0604 "${MUNGE_KEYFILE}" &&
    munged_start --force &&
    munged_stop &&
    grep "Warning:.* Keyfile.* readable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is writable by other.
#
test_expect_success 'keyfile writable by other failure' '
    chmod 0602 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start &&
    grep "Error:.* Keyfile.* writable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is writable by other.
#
test_expect_success 'keyfile writable by other override' '
    chmod 0602 "${MUNGE_KEYFILE}" &&
    munged_start --force &&
    munged_stop &&
    grep "Warning:.* Keyfile.* writable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check a keyfile with secure permissions.
# Note that this restores keyfile secure permissions for the remaining checks.
#
test_expect_success 'keyfile secure perms' '
    chmod 0600 "${MUNGE_KEYFILE}" &&
    munged_start &&
    munged_stop
'

# Check a keyfile dir that is owned by the EUID.
#
test_expect_success 'keyfile dir owned by euid' '
    local dir_uid my_euid &&
    dir_uid=$(ls -d -l -n "${MUNGE_KEYDIR}" | awk "{ print \$3 }") &&
    my_euid=$(id -u) &&
    test "${dir_uid}" = "${my_euid}" &&
    munged_start &&
    munged_stop
'

# Create an alternate keyfile dir that can be chown'd.
# This dir is placed in a subdir of [TMPDIR] since chowning something as root
#   can fail if NFS is configured for squashed access.
# Provide [ALT_KEYDIR] and [ALT_KEYFILE] for later tests.
#
test_expect_success SUDO 'alt keyfile dir setup' '
    ALT_KEYDIR="${TMPDIR:-"/tmp"}/munge-$$/alt-etc-$$" &&
    mkdir -m 0755 -p "${ALT_KEYDIR}" &&
    ALT_KEYFILE="${ALT_KEYDIR}/munged.key.$$" &&
    cp -p "${MUNGE_KEYFILE}" "${ALT_KEYFILE}" &&
    test_set_prereq ALT
'

# Check a keyfile dir that is owned by root.
#
test_expect_success ALT,SUDO 'keyfile dir owned by root' '
    sudo chown root "${ALT_KEYDIR}" &&
    munged_start --key-file="${ALT_KEYFILE}" &&
    munged_stop
'

# Check for an error when the keyfile dir is not owned by the EUID or root.
#
test_expect_success ALT,SUDO 'keyfile dir owned by other failure' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_KEYDIR}" &&
    test_must_fail munged_start --key-file="${ALT_KEYFILE}" &&
    grep "Error:.* Keyfile is insecure: invalid ownership" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile dir is not owned by
#   the EUID or root.
#
test_expect_success ALT,SUDO 'keyfile dir owned by other override' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_KEYDIR}" &&
    munged_start --key-file="${ALT_KEYFILE}" --force &&
    munged_stop &&
    grep "Warning:.* Keyfile is insecure: invalid ownership" "${MUNGE_LOGFILE}"
'

# Cleanup the alternate keyfile dir.
#
test_expect_success ALT,SUDO 'alt keyfile dir cleanup' '
    sudo rm -r -f "${ALT_KEYDIR}" &&
    if rmdir "$(dirname "${ALT_KEYDIR}")" 2>/dev/null; then :; fi &&
    unset ALT_KEYDIR &&
    unset ALT_KEYFILE
'

# Check if the keyfile dir can be writable (without the sticky bit) by a group
#   that matches the specified trusted group.
#
test_expect_success 'keyfile dir writable by trusted group' '
    local gid &&
    gid=$(ls -d -l -n "${MUNGE_KEYDIR}" | awk "{ print \$4 }") &&
    chmod 0770 "${MUNGE_KEYDIR}" &&
    munged_start --trusted-group="${gid}" &&
    munged_stop &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Check for an error when the keyfile dir is writable (without the sticky bit)
#   by a group that does not match the specified trusted group.
#
test_expect_success 'keyfile dir writable by untrusted group failure' '
    local gid &&
    gid=$(ls -d -l -n "${MUNGE_KEYDIR}" | awk "{ print \$4 }") &&
    gid=$((gid + 1)) &&
    chmod 0770 "${MUNGE_KEYDIR}" &&
    test_must_fail munged_start --trusted-group="${gid}" &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Check for an error when the keyfile dir is writable by group without the
#   sticky bit set.
#
test_expect_success 'keyfile dir writable by group failure' '
    chmod 0770 "${MUNGE_KEYDIR}" &&
    test_must_fail munged_start &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    grep "Error:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile dir is writable by
#   group without the sticky bit set.
#
test_expect_success 'keyfile dir writable by group override' '
    chmod 0770 "${MUNGE_KEYDIR}" &&
    munged_start --force &&
    munged_stop &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    grep "Warning:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the keyfile dir can be writable by group with the sticky bit set.
#
test_expect_success 'keyfile dir writable by group with sticky bit' '
    chmod 1770 "${MUNGE_KEYDIR}" &&
    munged_start &&
    munged_stop &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Check for an error when the keyfile dir is writable by other without the
#   sticky bit set.
#
test_expect_success 'keyfile dir writable by other failure' '
    chmod 0707 "${MUNGE_KEYDIR}" &&
    test_must_fail munged_start &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    grep "Error:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile dir is writable by
#   other without the sticky bit set.
#
test_expect_success 'keyfile dir writable by other override' '
    chmod 0707 "${MUNGE_KEYDIR}" &&
    munged_start --force &&
    munged_stop &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    grep "Warning:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the keyfile dir can be writable by other with the sticky bit set.
#
test_expect_success 'keyfile dir writable by other with sticky bit' '
    chmod 1707 "${MUNGE_KEYDIR}" &&
    munged_start &&
    munged_stop &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

test_done
