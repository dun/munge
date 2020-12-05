#!/bin/sh

test_description='Check munged security of socket'

. "$(dirname "$0")/sharness.sh"

# Set up the environment for checking the socket.
# MUNGE_SOCKETDIR is redefined to add a sub-directory for testing changes to
#   directory ownership and permissions.  It is kept in TMPDIR since NFS can
#   cause problems for the lockfile (the location of which is derived from the
#   socket name),
##
test_expect_success 'setup' '
    MUNGE_SOCKETDIR="${TMPDIR:-"/tmp"}/munge-$$/socketdir-$$" &&
    munged_setup &&
    munged_create_key
'

# Check the permissions on the socket dir.
##
test_expect_success 'socket dir perms' '
    test "$(find "${MUNGE_SOCKETDIR}" -type d -perm 1777)" = \
            "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Check the file type and permissions on the socket.
# MUNGE_SOCKET must be examined while munged is running since the socket is
#   removed when the daemon terminates.
# Testing TYPE and PERM after munged terminates allows the daemon to be stopped
#   even if the tests fail.
##
test_expect_success 'socket type and perms' '
    local TYPE PERM &&
    munged_start_daemon &&
    TYPE=$(find "${MUNGE_SOCKET}" -type s) &&
    PERM=$(find "${MUNGE_SOCKET}" -perm 0777) &&
    munged_stop_daemon &&
    test "${TYPE}" = "${MUNGE_SOCKET}" &&
    test "${PERM}" = "${MUNGE_SOCKET}"
'

# Check a socket dir that is owned by the EUID.
##
test_expect_success 'socket dir owned by euid' '
    local DIR_UID MY_EUID &&
    DIR_UID=$(ls -d -l -n "${MUNGE_SOCKETDIR}" | awk "{ print \$3 }") &&
    MY_EUID=$(id -u) &&
    test "${DIR_UID}" = "${MY_EUID}" &&
    munged_start_daemon &&
    munged_stop_daemon
'

# Create an alternate socket dir that can be chwon'd.
# This dir is placed in a subdir of TMPDIR since chowning something as root can
#   fail if NFS is configured for squashed access.
##
test_expect_success SUDO 'alt socket dir setup' '
    ALT_SOCKETDIR="${TMPDIR:-"/tmp"}/munge-$$/alt-socketdir-$$" &&
    mkdir -m 1777 -p "${ALT_SOCKETDIR}" &&
    ALT_SOCKET="${ALT_SOCKETDIR}/munged.sock.$$" &&
    test_set_prereq ALT
'

# Check a socket dir that is owned by root.
##
test_expect_success ALT,SUDO 'socket dir owned by root' '
    sudo chown root "${ALT_SOCKETDIR}" &&
    munged_start_daemon --socket="${ALT_SOCKET}" &&
    munged_stop_daemon --socket="${ALT_SOCKET}"
'

# Check for an error when the socket dir is not owned by the EUID or root.
##
test_expect_success ALT,SUDO 'socket dir owned by other failure' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_SOCKETDIR}" &&
    test_must_fail munged_start_daemon --socket="${ALT_SOCKET}" &&
    egrep "Error:.* Socket.* invalid ownership of \"${ALT_SOCKETDIR}\"" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the socket dir is not owned by the
#   EUID or root.
##
test_expect_success ALT,SUDO 'socket dir owned by other override' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_SOCKETDIR}" &&
    munged_start_daemon --socket="${ALT_SOCKET}" --force &&
    munged_stop_daemon --socket="${ALT_SOCKET}" &&
    egrep "Warning:.* Socket.* invalid ownership of \"${ALT_SOCKETDIR}\"" \
            "${MUNGE_LOGFILE}"
'

# Cleanup the alternate socket dir.
##
test_expect_success ALT 'alt socket dir cleanup' '
    rmdir "${ALT_SOCKETDIR}" &&
    unset ALT_SOCKETDIR &&
    unset ALT_SOCKET
'

# Check if the socket dir can be writable by group (without the sticky bit set)
#   when a trusted group is specified that matches the directory's group.
##
test_expect_success 'socket dir writable by trusted group' '
    local GID &&
    GID=$(ls -d -l -n "${MUNGE_SOCKETDIR}" | awk "{ print \$4 }") &&
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon --trusted-group="${GID}" &&
    munged_stop_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir is writable (without the sticky bit
#   set) by a group that does not match the specified trusted group.
##
test_expect_success 'socket dir writable by untrusted group failure' '
    local GID &&
    GID=$(ls -d -l -n "${MUNGE_SOCKETDIR}" | awk "{ print \$4 }") &&
    GID=$(( ${GID} + 1 )) &&
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start_daemon --trusted-group="${GID}" &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir is writable by group without the
#   sticky bit set.
##
test_expect_success 'socket dir writable by group failure' '
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    egrep "Error:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the socket dir is writable by group
#   without the sticky bit set.
##
test_expect_success 'socket dir writable by group override' '
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    egrep "Warning:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the socket dir can be writable by group with the sticky bit set.
##
test_expect_success 'socket dir writable by group with sticky bit' '
    chmod 1771 "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir is writable by other without the
#   sticky bit set.
##
test_expect_success 'socket dir writable by other failure' '
    chmod 0717 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    egrep "Error:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the socket dir is writable by other
#   without the sticky bit set.
##
test_expect_success 'socket dir writable by other override' '
    chmod 0717 "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    egrep "Warning:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the socket dir can be writable by other with the sticky bit set.
##
test_expect_success 'socket dir writable by other with sticky bit' '
    chmod 1717 "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon &&
    munged_stop_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir does not have execute permissions
#   for all.
##
test_expect_success 'socket dir inaccessible by all failure' '
    chmod 0700 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    egrep "Error:.* Socket is inaccessible.* \"${MUNGE_SOCKETDIR}\"" \
            "${MUNGE_LOGFILE}"
'

#
# Check if the error can be overridden when the socket dir does not have
#   execute permissions for all.
##
test_expect_success 'socket dir inaccessible by all override' '
    chmod 0700 "${MUNGE_SOCKETDIR}" &&
    munged_start_daemon --force &&
    munged_stop_daemon &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    egrep "Warning:.* Socket is inaccessible.* \"${MUNGE_SOCKETDIR}\"" \
            "${MUNGE_LOGFILE}"
'

# Clean up detritus from testing.  This may include an errant munged process
#   that has not terminated.
##
test_expect_success 'cleanup' '
    rmdir "${MUNGE_SOCKETDIR}" &&
    if rmdir "$(dirname "${MUNGE_SOCKETDIR}")" 2>/dev/null; then :; fi &&
    munged_cleanup
'

test_done
