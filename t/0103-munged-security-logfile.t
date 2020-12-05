#!/bin/sh

test_description='Check munged security of logfile'

. "$(dirname "$0")/sharness.sh"

# Set up the environment for checking the logfile.
##
test_expect_success 'setup' '
    munged_setup &&
    munged_create_key
'

# Check startup with an existing empty logfile.  The same file (identified by
#   its inode number) should exist after the daemon terminates, but it should
#   no longer be empty.
##
test_expect_success 'logfile regular file' '
    local INODE0 INODE1 &&
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    INODE0=$(ls -i "${MUNGE_LOGFILE}" | awk "{ print \$1 }") &&
    munged_start_daemon t-keep-logfile &&
    munged_stop_daemon &&
    INODE1=$(ls -i "${MUNGE_LOGFILE}" | awk "{ print \$1 }") &&
    test "${INODE0}" -eq "${INODE1}" &&
    test -s "${MUNGE_LOGFILE}"
'

# Check for an error when the logfile is a symlink to a regular file.
##
test_expect_success 'logfile symlink to regular file failure' '
    local MY_LOGFILE &&
    MY_LOGFILE="${MUNGE_LOGFILE}.symlink" &&
    ln -s -f "${MUNGE_LOGFILE}" "${MY_LOGFILE}" &&
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile \
            --log-file="${MY_LOGFILE}" 2>err.$$ &&
    egrep "Error:.* Logfile.* should not be a symbolic link" err.$$
'

# Check if the error can be overridden when the logfile is a symlink to a
#   regular file.
##
test_expect_success 'logfile symlink to regular file override' '
    local MY_LOGFILE &&
    MY_LOGFILE="${MUNGE_LOGFILE}.symlink" &&
    ln -s -f "${MUNGE_LOGFILE}" "${MY_LOGFILE}" &&
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    munged_start_daemon t-keep-logfile --log-file="${MY_LOGFILE}" --force \
            2>err.$$ &&
    munged_stop_daemon &&
    egrep "Warning:.* Logfile.* should not be a symbolic link" err.$$
'

# Check startup without an existing logfile (by not specifying t-keep-logfile
#   so as to remove an existing logfile).  A non-empty logfile should exist
#   after the daemon terminates.
##
test_expect_success 'logfile missing' '
    munged_start_daemon &&
    munged_stop_daemon &&
    test -s "${MUNGE_LOGFILE}"
'

# Check for an error when the logfile is a symlink to a non-existent file
#   (by not specifying t-keep-logfile so as to remove an existing logfile).
##
test_expect_success 'logfile symlink to missing file failure' '
    local MY_LOGFILE &&
    MY_LOGFILE="${MUNGE_LOGFILE}.symlink" &&
    ln -s -f "${MUNGE_LOGFILE}" "${MY_LOGFILE}" &&
    test_must_fail munged_start_daemon --log-file="${MY_LOGFILE}" 2>err.$$ &&
    egrep "Error:.* Logfile.* should not be a symbolic link" err.$$
'

# Check if the error can be overridden when the logfile is a symlink to a
#   non-existent file (by not specifying t-keep-logfile so as to remove an
#   existing logfile).  A non-empty logfile should exist after the daemon
#   terminates.
##
test_expect_success 'logfile symlink to missing file override' '
    local MY_LOGFILE &&
    MY_LOGFILE="${MUNGE_LOGFILE}.symlink" &&
    ln -s -f "${MUNGE_LOGFILE}" "${MY_LOGFILE}" &&
    munged_start_daemon --log-file="${MY_LOGFILE}" --force 2>err.$$ &&
    munged_stop_daemon &&
    egrep "Warning:.* Logfile.* should not be a symbolic link" err.$$ &&
    test -s "${MUNGE_LOGFILE}"
'

# Check for an error when the logfile is not a regular file.
# Using a directory for the non-regular-file seems the most portable solution.
##
test_expect_success 'logfile non-regular-file failure' '
    local MUNGE_LOGFILE &&
    MUNGE_LOGFILE="${MUNGE_LOGDIR}/munged.log.$$.non-regular-file" &&
    rm -f "${MUNGE_LOGFILE}" &&
    mkdir "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile 2>err.$$ &&
    egrep "Error:.* Logfile.* must be a regular file" err.$$ &&
    rmdir "${MUNGE_LOGFILE}"
'

# Check that the error cannot be overridden when the logfile is not a regular
#   file.
##
test_expect_success 'logfile non-regular-file override failure' '
    local MUNGE_LOGFILE &&
    MUNGE_LOGFILE="${MUNGE_LOGDIR}/munged.log.$$.non-regular-file" &&
    rm -f "${MUNGE_LOGFILE}" &&
    mkdir "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile --force 2>err.$$ &&
    egrep "Error:.* Logfile.* must be a regular file" err.$$ &&
    rmdir "${MUNGE_LOGFILE}"
'

# Check for an error when the logfile is not writable by user.
# Skip this test if running as root since the root user will not get the
#   expected EACCESS failure.
##
test_expect_success !ROOT 'logfile not writable by user failure' '
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0400 "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile 2>err.$$ &&
    egrep "Error:.* Failed to open logfile.* Permission denied" err.$$
'

# Check if the logfile can be writable by a group that matches the specified
#   trusted group.
##
test_expect_failure 'logfile writable by trusted group ' '
    local GID &&
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0620 "${MUNGE_LOGFILE}" &&
    GID=$(ls -l -n "${MUNGE_LOGFILE}" | awk "{ print \$4 }") &&
    munged_start_daemon t-keep-logfile --trusted-group="${GID}" &&
    munged_stop_daemon
'

# Check for an error when the logfile is writable by a group that does not
#   match the specified trusted group.
##
test_expect_success 'logfile writable by untrusted group failure' '
    local GID &&
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0620 "${MUNGE_LOGFILE}" &&
    GID=$(ls -l -n "${MUNGE_LOGFILE}" | awk "{ print \$4 }") &&
    GID=$(( ${GID} + 1 )) &&
    test_must_fail munged_start_daemon t-keep-logfile --trusted-group="${GID}"
'

# Check for an error when the logfile is writable by group.
##
test_expect_success 'logfile writable by group failure' '
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0620 "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile 2>err.$$ &&
    egrep "Error:.* Logfile.* writable.* by.* group" err.$$
'

# Check if the error can be overridden when the logfile is writable by group.
##
test_expect_success 'logfile writable by group override' '
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0620 "${MUNGE_LOGFILE}" &&
    munged_start_daemon t-keep-logfile --force 2>err.$$ &&
    munged_stop_daemon &&
    egrep "Warning:.* Logfile.* writable.* by.* group" err.$$
'

# Check for an error when the logfile is writable by other.
##
test_expect_success 'logfile writable by other failure' '
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0602 "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile 2>err.$$ &&
    egrep "Error:.* Logfile.* writable.* by.* other" err.$$
'

# Check if the error can be overridden when the logfile is writable by other.
##
test_expect_success 'logfile writable by other override' '
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0602 "${MUNGE_LOGFILE}" &&
    munged_start_daemon t-keep-logfile --force 2>err.$$ &&
    munged_stop_daemon &&
    egrep "Warning:.* Logfile.* writable.* by.* other" err.$$
'

# Check if the logfile can be readable by all.
##
test_expect_success 'logfile readable by all' '
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0644 "${MUNGE_LOGFILE}" &&
    munged_start_daemon t-keep-logfile &&
    munged_stop_daemon
'

# Check a logfile dir that is owned by the EUID.
##
test_expect_success 'logfile dir owned by euid' '
    local DIR_UID MY_EUID &&
    DIR_UID=$(ls -d -l -n "${MUNGE_LOGDIR}" | awk "{ print \$3 }") &&
    MY_EUID=$(id -u) &&
    test "${DIR_UID}" = "${MY_EUID}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Create an alternate logfile dir that can be chown'd.
# This dir is placed in a subdir of TMPDIR since chowning something as root can
#   fail if NFS is configured for squashed access.
##
test_expect_success SUDO 'alt logfile dir setup' '
    ALT_LOGDIR="${TMPDIR:-"/tmp"}/munge-$$/alt-log-$$" &&
    mkdir -m 0755 -p "${ALT_LOGDIR}" &&
    ALT_LOGFILE="${ALT_LOGDIR}/munged.log.$$" &&
    touch "${ALT_LOGFILE}" &&
    test_set_prereq ALT
'

# Check a logfile dir that is owned by root.
##
test_expect_success ALT,SUDO 'logfile dir owned by root' '
    sudo chown root "${ALT_LOGDIR}" &&
    > "${ALT_LOGFILE}" &&
    munged_start_daemon --log-file="${ALT_LOGFILE}" &&
    munged_stop_daemon
'

# Check for an error when the logfile dir is not owned by the EUID or root.
##
test_expect_success ALT,SUDO 'logfile dir owned by other failure' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_LOGDIR}" &&
    > "${ALT_LOGFILE}" &&
    test_must_fail munged_start_daemon --log-file="${ALT_LOGFILE}" 2>err.$$ &&
    egrep "Error:.* Logfile.* invalid ownership of \"${ALT_LOGDIR}\"" err.$$
'

# Check if the error can be overridden when the logfile dir is not owned by
#   the EUID or root.
##
test_expect_success ALT,SUDO 'logfile dir owned by other override' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_LOGDIR}" &&
    > "${ALT_LOGFILE}" &&
    munged_start_daemon --log-file="${ALT_LOGFILE}" --force 2>err.$$ &&
    munged_stop_daemon &&
    egrep "Warning:.* Logfile.* invalid ownership of \"${ALT_LOGDIR}\"" err.$$
'

# Cleanup the alternate logfile dir.
##
test_expect_success ALT,SUDO 'alt logfile dir cleanup' '
    sudo rm -r -f "${ALT_LOGDIR}" &&
    if rmdir "$(dirname "${ALT_LOGDIR}")" 2>/dev/null; then :; fi &&
    unset ALT_LOGDIR &&
    unset ALT_LOGFILE
'

# Check if the logfile dir can be writable (without the sticky bit) by a group
#   that matches the specified trusted group.
##
test_expect_success 'logfile dir writable by trusted group ' '
    local GID &&
    GID=$(ls -d -l -n "${MUNGE_LOGDIR}" | awk "{ print \$4 }") &&
    chmod 0770 "${MUNGE_LOGDIR}" &&
    munged_start_daemon --trusted-group="${GID}" &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_LOGDIR}"
'

# Check if the logfile dir can be writable (without the sticky bit) by a group
#   that does not match the specified trusted group.
# Group-writable permissions are allowed on the logfile dir (see Issue #31).
##
test_expect_success 'logfile dir writable by untrusted group failure' '
    local GID &&
    GID=$(ls -d -l -n "${MUNGE_LOGDIR}" | awk "{ print \$4 }") &&
    GID=$(( ${GID} + 1 )) &&
    chmod 0770 "${MUNGE_LOGDIR}" &&
    munged_start_daemon --trusted-group="${GID}" &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_LOGDIR}"
'

# Check if the logfile dir can be writable by group without the sticky bit set.
# Group-writable permissions are allowed on the logfile dir (see Issue #31).
##
test_expect_success 'logfile dir writable by group' '
    chmod 0770 "${MUNGE_LOGDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_LOGDIR}"
'

# Check if the logfile dir can be writable by group with the sticky bit set.
##
test_expect_success 'logfile dir writable by group with sticky bit' '
    chmod 1770 "${MUNGE_LOGDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_LOGDIR}"
'

# Check for an error when the logfile dir is writable by other without the
#   sticky bit set.
##
test_expect_success 'logfile dir writable by other failure' '
    chmod 0707 "${MUNGE_LOGDIR}" &&
    test_must_fail munged_start_daemon 2>err.$$ &&
    chmod 0755 "${MUNGE_LOGDIR}" &&
    egrep "Error:.* world-writable permissions without sticky bit set" err.$$
'

# Check if the error can be overridden when the logfile dir is writable by
#   other without the sticky bit set.
##
test_expect_success 'logfile dir writable by other override' '
    chmod 0707 "${MUNGE_LOGDIR}" &&
    munged_start_daemon --force 2>err.$$ &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_LOGDIR}" &&
    egrep "Warning:.* world-writable permissions without sticky bit set" err.$$
'

# Check if the logfile dir can be writable by other with the sticky bit set.
##
test_expect_success 'logfile dir writable by other with sticky bit' '
    chmod 1707 "${MUNGE_LOGDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 0755 "${MUNGE_LOGDIR}"
'

# Check for a regression of a duplicate error message being written to stderr.
# To generate an error, test for the logfile being writable by other since this
#   will not be affected by root privileges.
#
##
test_expect_success 'logfile failure writes single message to stderr' '
    local ERR NUM &&
    rm -f "${MUNGE_LOGFILE}" &&
    touch "${MUNGE_LOGFILE}" &&
    chmod 0602 "${MUNGE_LOGFILE}" &&
    test_must_fail munged_start_daemon t-keep-logfile 2>err.$$ &&
    cat err.$$ &&
    ERR=$(sed -n -e "s/.*Error: //p" err.$$ | sort | uniq -c | sort -n -r) &&
    NUM=$(echo "${ERR}" | awk "{ print \$1; exit }") &&
    test "${NUM}" -eq 1 2>/dev/null
'

# Clean up after a munged process that may not have terminated.
##
test_expect_success 'cleanup' '
    munged_cleanup
'

test_done
