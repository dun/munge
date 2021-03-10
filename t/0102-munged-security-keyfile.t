#!/bin/sh

test_description='Check munged security of keyfile'

. "$(dirname "$0")/sharness.sh"

# Set up the environment for checking the keyfile.
##
test_expect_success 'setup' '
    munged_setup &&
    munged_create_key
'

# Check a keyfile that is a regular file.
##
test_expect_success 'keyfile regular file' '
    test -f "${MUNGE_KEYFILE}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Check for an error when the keyfile is missing.
##
test_expect_success 'keyfile missing failure' '
    local MUNGE_KEYFILE &&
    MUNGE_KEYFILE="${MUNGE_KEYDIR}/munged.key.$$.missing" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Failed to find keyfile.*: No such file" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is not a regular file.
# Using a directory for the non-regular-file seems the most portable solution.
##
test_expect_success 'keyfile non-regular-file failure' '
    local MUNGE_KEYFILE &&
    MUNGE_KEYFILE="${MUNGE_KEYDIR}/munged.key.$$.non-regular-file" &&
    rm -r -f "${MUNGE_KEYFILE}" &&
    mkdir "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Keyfile.* must be a regular file" "${MUNGE_LOGFILE}" &&
    rmdir "${MUNGE_KEYFILE}"
'

# Check that the error cannot be overridden when the keyfile is not a regular
#   file.
##
test_expect_success 'keyfile non-regular-file override failure' '
    local MUNGE_KEYFILE &&
    MUNGE_KEYFILE="${MUNGE_KEYDIR}/munged.key.$$.non-regular-file" &&
    rm -r -f "${MUNGE_KEYFILE}" &&
    mkdir "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon --force &&
    egrep "Error:.* Keyfile.* must be a regular file" "${MUNGE_LOGFILE}" &&
    rmdir "${MUNGE_KEYFILE}"
'

# Check for an error when the keyfile is a symlink to a regular file.
##
test_expect_success 'keyfile symlink to regular file failure' '
    local MY_KEYFILE &&
    MY_KEYFILE="${MUNGE_KEYFILE}.symlink" &&
    ln -s -f "${MUNGE_KEYFILE}" "${MY_KEYFILE}" &&
    test_must_fail munged_start_daemon --key-file="${MY_KEYFILE}" &&
    egrep "Error:.* Keyfile.* a symbolic link" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is a symlink to a
#   regular file.
##
test_expect_success 'keyfile symlink to regular file override' '
    local MY_KEYFILE &&
    MY_KEYFILE="${MUNGE_KEYFILE}.symlink" &&
    ln -s -f "${MUNGE_KEYFILE}" "${MY_KEYFILE}" &&
    munged_start_daemon --key-file="${MY_KEYFILE}" --force &&
    munged_stop_daemon &&
    egrep "Warning:.* Keyfile.* a symbolic link" "${MUNGE_LOGFILE}"
'

# Check a keyfile owned by the EUID.
##
test_expect_success 'keyfile owned by euid' '
    local KEY_UID MY_EUID &&
    KEY_UID=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$3 }") &&
    MY_EUID=$(id -u) &&
    test "${KEY_UID}" = "${MY_EUID}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Check if the keyfile can be readable by a group that matches the specified
#   trusted group.
##
test_expect_failure 'keyfile readable by trusted group' '
    local GID &&
    GID=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    chmod 0640 "${MUNGE_KEYFILE}" &&
    munged_start_daemon --trusted-group="${GID}" &&
    munged_stop_daemon
'

# Check for an error when the keyfile is readable by a group that does not
#   match the specified trusted group.
##
test_expect_success 'keyfile readable by untrusted group failure' '
    local GID &&
    GID=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    GID=$(( ${GID} + 1 )) &&
    chmod 0640 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon --trusted-group="${GID}"
'

# Check if the keyfile can be writable by a group that matches the specified
#   trusted group.
##
test_expect_failure 'keyfile writable by trusted group' '
    local GID &&
    GID=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    chmod 0620 "${MUNGE_KEYFILE}" &&
    munged_start_daemon --trusted-group="${GID}" &&
    munged_stop_daemon
'

# Check for an error when the keyfile is writable by a group that does not
#   match the specified trusted group.
##
test_expect_success 'keyfile writable by untrusted group failure' '
    local GID &&
    GID=$(ls -l -n "${MUNGE_KEYFILE}" | awk "{ print \$4 }") &&
    GID=$(( ${GID} + 1 )) &&
    chmod 0620 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon --trusted-group="${GID}"
'

# Check for an error when the keyfile is readable by group.
##
test_expect_success 'keyfile readable by group failure' '
    chmod 0640 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Keyfile.* readable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is readable by group.
##
test_expect_success 'keyfile readable by group override' '
    chmod 0640 "${MUNGE_KEYFILE}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    egrep "Warning:.* Keyfile.* readable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is writable by group.
##
test_expect_success 'keyfile writable by group failure' '
    chmod 0620 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Keyfile.* writable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is writable by group.
##
test_expect_success 'keyfile writable by group override' '
    chmod 0620 "${MUNGE_KEYFILE}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    egrep "Warning:.* Keyfile.* writable.* by.* group" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is readable by other.
##
test_expect_success 'keyfile readable by other failure' '
    chmod 0604 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Keyfile.* readable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is readable by other.
##
test_expect_success 'keyfile readable by other override' '
    chmod 0604 "${MUNGE_KEYFILE}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    egrep "Warning:.* Keyfile.* readable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check for an error when the keyfile is writable by other.
##
test_expect_success 'keyfile writable by other failure' '
    chmod 0602 "${MUNGE_KEYFILE}" &&
    test_must_fail munged_start_daemon &&
    egrep "Error:.* Keyfile.* writable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile is writable by other.
##
test_expect_success 'keyfile writable by other override' '
    chmod 0602 "${MUNGE_KEYFILE}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    egrep "Warning:.* Keyfile.* writable.* by.* other" "${MUNGE_LOGFILE}"
'

# Check a keyfile with secure permissions.
# Note that this restores keyfile secure permissions for the remaining checks.
##
test_expect_success 'keyfile secure perms' '
    chmod 0600 "${MUNGE_KEYFILE}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Check a keyfile dir that is owned by the EUID.
##
test_expect_success 'keyfile dir owned by euid' '
    local DIR_UID MY_EUID &&
    DIR_UID=$(ls -d -l -n "${MUNGE_KEYDIR}" | awk "{ print \$3 }") &&
    MY_EUID=$(id -u) &&
    test "${DIR_UID}" = "${MY_EUID}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Create an alternate keyfile dir that can be chown'd.
# This dir is placed in a subdir of TMPDIR since chowning something as root can
#   fail if NFS is configured for squashed access.
##
test_expect_success SUDO 'alt keyfile dir setup' '
    ALT_KEYDIR="${TMPDIR:-"/tmp"}/munge-$$/alt-etc-$$" &&
    mkdir -m 0755 -p "${ALT_KEYDIR}" &&
    ALT_KEYFILE="${ALT_KEYDIR}/munged.key.$$" &&
    cp -p "${MUNGE_KEYFILE}" "${ALT_KEYFILE}" &&
    test_set_prereq ALT
'

# Check a keyfile dir that is owned by root.
##
test_expect_success ALT,SUDO 'keyfile dir owned by root' '
    sudo chown root "${ALT_KEYDIR}" &&
    munged_start_daemon --key-file="${ALT_KEYFILE}" &&
    munged_stop_daemon
'

# Check for an error when the keyfile dir is not owned by the EUID or root.
##
test_expect_success ALT,SUDO 'keyfile dir owned by other failure' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_KEYDIR}" &&
    test_must_fail munged_start_daemon --key-file="${ALT_KEYFILE}" &&
    egrep "Error:.* Keyfile.* invalid ownership of \"${ALT_KEYDIR}\"" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile dir is not owned by
#   the EUID or root.
##
test_expect_success ALT,SUDO 'keyfile dir owned by other override' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_KEYDIR}" &&
    munged_start_daemon --key-file="${ALT_KEYFILE}" --force &&
    munged_stop_daemon &&
    egrep "Warning:.* Keyfile.* invalid ownership of \"${ALT_KEYDIR}\"" \
            "${MUNGE_LOGFILE}"
'

# Cleanup the alternate keyfile dir.
##
test_expect_success ALT,SUDO 'alt keyfile dir cleanup' '
    sudo rm -r -f "${ALT_KEYDIR}" &&
    if rmdir "$(dirname "${ALT_KEYDIR}")" 2>/dev/null; then :; fi &&
    unset ALT_KEYDIR &&
    unset ALT_KEYFILE
'

# Check if the keyfile dir can be writable (without the sticky bit) by a group
#   that matches the specified trusted group.
##
test_expect_success 'keyfile dir writable by trusted group' '
    local GID &&
    GID=$(ls -d -l -n "${MUNGE_KEYDIR}" | awk "{ print \$4 }") &&
    chmod 0770 "${MUNGE_KEYDIR}" &&
    munged_start_daemon --trusted-group="${GID}" &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Check for an error when the keyfile dir is writable (without the sticky bit)
#   by a group that does not match the specified trusted group.
##
test_expect_success 'keyfile dir writable by untrusted group failure' '
    local GID &&
    GID=$(ls -d -l -n "${MUNGE_KEYDIR}" | awk "{ print \$4 }") &&
    GID=$(( ${GID} + 1 )) &&
    chmod 0770 "${MUNGE_KEYDIR}" &&
    test_must_fail munged_start_daemon --trusted-group="${GID}" &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Check for an error when the keyfile dir is writable by group without the
#   sticky bit set.
##
test_expect_success 'keyfile dir writable by group failure' '
    chmod 0770 "${MUNGE_KEYDIR}" &&
    test_must_fail munged_start_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    egrep "Error:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile dir is writable by
#   group without the sticky bit set.
##
test_expect_success 'keyfile dir writable by group override' '
    chmod 0770 "${MUNGE_KEYDIR}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    egrep "Warning:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the keyfile dir can be writable by group with the sticky bit set.
##
test_expect_success 'keyfile dir writable by group with sticky bit' '
    chmod 1770 "${MUNGE_KEYDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Check for an error when the keyfile dir is writable by other without the
#   sticky bit set.
##
test_expect_success 'keyfile dir writable by other failure' '
    chmod 0707 "${MUNGE_KEYDIR}" &&
    test_must_fail munged_start_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    egrep "Error:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the keyfile dir is writable by
#   other without the sticky bit set.
##
test_expect_success 'keyfile dir writable by other override' '
    chmod 0707 "${MUNGE_KEYDIR}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}" &&
    egrep "Warning:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the keyfile dir can be writable by other with the sticky bit set.
##
test_expect_success 'keyfile dir writable by other with sticky bit' '
    chmod 1707 "${MUNGE_KEYDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_KEYDIR}"
'

# Clean up after a munged process that may not have terminated.
##
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
