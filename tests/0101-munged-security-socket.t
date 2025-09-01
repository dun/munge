#!/bin/sh

test_description='Check munged security of socket'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Set up the environment.
# Redefine [MUNGE_SOCKETDIR] to add a sub-directory for testing changes to
#   directory ownership and permissions.  It is kept in [TMPDIR] since NFS can
#   cause problems for the lockfile (the location of which is derived from the
#   socket name),
#
test_expect_success 'setup' '
    MUNGE_SOCKETDIR="${TMPDIR:-"/tmp"}/munge-$$/socketdir-$$" &&
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

# Check the permissions on the socket dir.
#
test_expect_success 'socket dir perms' '
    ls -ld "${MUNGE_SOCKETDIR}" | grep "^drwxrwxrwt" &&
    munged_start &&
    munged_stop
'

# Check the file type and permissions on the socket.
# [MUNGE_SOCKET] must be examined while munged is running since the socket is
#   removed when the daemon terminates.  The type and permission check must be
#   done after the daemon is stopped in case the check fails and breaks the
#   &&-chain.
#
test_expect_success 'socket type and perms' '
    munged_start &&
    ls_out=$(ls -ld "${MUNGE_SOCKET}") &&
    munged_stop &&
    echo "${ls_out}" | grep "^srwxrwxrwx"
'

# Check a socket dir that is owned by the EUID.
#
test_expect_success 'socket dir owned by euid' '
    dir_uid=$(ls -d -l -n "${MUNGE_SOCKETDIR}" | awk "{ print \$3 }") &&
    my_euid=$(id -u) &&
    test "${dir_uid}" = "${my_euid}" &&
    munged_start &&
    munged_stop
'

# Create an alternate socket dir that can be chown'd.
# This dir is placed in a subdir of [TMPDIR] since chowning something as root
#   can fail if NFS is configured for squashed access.
# Provide [ALT_SOCKETDIR] and [ALT_SOCKET] for later checks.
#
test_expect_success SUDO 'alt socket dir setup' '
    ALT_SOCKETDIR="${TMPDIR:-"/tmp"}/munge-$$/alt-socketdir-$$" &&
    mkdir -m 1777 -p "${ALT_SOCKETDIR}" &&
    ALT_SOCKET="${ALT_SOCKETDIR}/munged.sock.$$" &&
    test_set_prereq ALT
'

# Check a socket dir that is owned by root.
#
test_expect_success ALT,SUDO 'socket dir owned by root' '
    sudo chown root "${ALT_SOCKETDIR}" &&
    munged_start --socket="${ALT_SOCKET}" &&
    munged_stop --socket="${ALT_SOCKET}"
'

# Check for an error when the socket dir is not owned by the EUID or root.
#
test_expect_success ALT,SUDO 'socket dir owned by other failure' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_SOCKETDIR}" &&
    test_must_fail munged_start --socket="${ALT_SOCKET}" &&
    grep "Error:.* Socket is insecure: invalid ownership" "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the socket dir is not owned by the
#   EUID or root.
#
test_expect_success ALT,SUDO 'socket dir owned by other override' '
    test "$(id -u)" != "1" &&
    sudo chown 1 "${ALT_SOCKETDIR}" &&
    munged_start --socket="${ALT_SOCKET}" --force &&
    munged_stop --socket="${ALT_SOCKET}" &&
    grep "Warning:.* Socket is insecure: invalid ownership" "${MUNGE_LOGFILE}"
'

# Cleanup the alternate socket dir.
#
test_expect_success ALT 'alt socket dir cleanup' '
    rmdir "${ALT_SOCKETDIR}" &&
    unset ALT_SOCKETDIR &&
    unset ALT_SOCKET
'

# Check if the socket dir can be writable by group (without the sticky bit set)
#   when a trusted group is specified that matches the directory's group.
#
test_expect_success 'socket dir writable by trusted group' '
    gid=$(ls -d -l -n "${MUNGE_SOCKETDIR}" | awk "{ print \$4 }") &&
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    munged_start --trusted-group="${gid}" &&
    munged_stop &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir is writable (without the sticky bit
#   set) by a group that does not match the specified trusted group.
#
test_expect_success 'socket dir writable by untrusted group failure' '
    gid=$(ls -d -l -n "${MUNGE_SOCKETDIR}" | awk "{ print \$4 }") &&
    gid=$((gid + 1)) &&
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start --trusted-group="${gid}" &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir is writable by group without the
#   sticky bit set.
#
test_expect_success 'socket dir writable by group failure' '
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    grep "Error:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the socket dir is writable by group
#   without the sticky bit set.
#
test_expect_success 'socket dir writable by group override' '
    chmod 0771 "${MUNGE_SOCKETDIR}" &&
    munged_start --force &&
    munged_stop &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    grep "Warning:.* group-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the socket dir can be writable by group with the sticky bit set.
#
test_expect_success 'socket dir writable by group with sticky bit' '
    chmod 1771 "${MUNGE_SOCKETDIR}" &&
    munged_start &&
    munged_stop &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir is writable by other without the
#   sticky bit set.
#
test_expect_success 'socket dir writable by other failure' '
    chmod 0717 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    grep "Error:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the error can be overridden when the socket dir is writable by other
#   without the sticky bit set.
#
test_expect_success 'socket dir writable by other override' '
    chmod 0717 "${MUNGE_SOCKETDIR}" &&
    munged_start --force &&
    munged_stop &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    grep "Warning:.* world-writable permissions without sticky bit set" \
            "${MUNGE_LOGFILE}"
'

# Check if the socket dir can be writable by other with the sticky bit set.
#
test_expect_success 'socket dir writable by other with sticky bit' '
    chmod 1717 "${MUNGE_SOCKETDIR}" &&
    munged_start &&
    munged_stop &&
    chmod 1777 "${MUNGE_SOCKETDIR}"
'

# Check for an error when the socket dir does not have execute permissions
#   for all.
#
test_expect_success 'socket dir inaccessible by all failure' '
    chmod 0700 "${MUNGE_SOCKETDIR}" &&
    test_must_fail munged_start &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    grep "Error:.* Socket.* execute permissions for all required" \
            "${MUNGE_LOGFILE}"
'

#
# Check if the error can be overridden when the socket dir does not have
#   execute permissions for all.
#
test_expect_success 'socket dir inaccessible by all override' '
    chmod 0700 "${MUNGE_SOCKETDIR}" &&
    munged_start --force &&
    munged_stop &&
    chmod 1777 "${MUNGE_SOCKETDIR}" &&
    grep "Warning:.* Socket.* execute permissions for all required" \
            "${MUNGE_LOGFILE}"
'

# Clean up detritus from testing.  This may include an errant munged process
#   that has not terminated.
# [MUNGE_SOCKETDIR] should be empty if munged gracefully terminated, so list
#   the directory contents to aid in debugging if needed.
#
test_expect_success 'cleanup' '
    munged_cleanup &&
    ls -A1 "${MUNGE_SOCKETDIR}" &&
    rmdir "${MUNGE_SOCKETDIR}" &&
    if rmdir "$(dirname "${MUNGE_SOCKETDIR}")" 2>/dev/null; then :; fi
'

test_done
