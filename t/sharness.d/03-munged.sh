# Requires MUNGED and MUNGEKEY.

##
# Setup directory tree and shell variables for testing.
# MUNGE_ROOT, MUNGE_SOCKETDIR, MUNGE_KEYDIR, MUNGE_LOGDIR, MUNGE_PIDDIR, and
#   MUNGE_SEEDDIR can be overridden by setting them beforehand.
# MUNGE_SOCKET is placed in TMPDIR by default since NFS can cause problems for
#   the lockfile.  Debian 3.1 returns an incorrect PID for the process holding
#   the lock across an NFS mount.  FreeBSD cannot create a lockfile across an
#   NFS mount.
##
munged_setup_env()
{
    : "${MUNGE_ROOT:="$(pwd)"}" &&
    mkdir -m 0755 -p "${MUNGE_ROOT}" &&

    : "${MUNGE_SOCKETDIR:="${TMPDIR:-"/tmp"}"}" &&
    MUNGE_SOCKET="${MUNGE_SOCKETDIR}/munged.sock.$$" &&
    mkdir -m 1777 -p "${MUNGE_SOCKETDIR}" &&

    : "${MUNGE_KEYDIR:="${MUNGE_ROOT}/etc"}" &&
    MUNGE_KEYFILE="${MUNGE_KEYDIR}/munged.key.$$" &&
    mkdir -m 0755 -p "${MUNGE_KEYDIR}" &&

    : "${MUNGE_LOGDIR:="${MUNGE_ROOT}/log"}" &&
    MUNGE_LOGFILE="${MUNGE_LOGDIR}/munged.log.$$" &&
    mkdir -m 0755 -p "${MUNGE_LOGDIR}" &&

    : "${MUNGE_PIDDIR:="${MUNGE_ROOT}/run"}" &&
    MUNGE_PIDFILE="${MUNGE_PIDDIR}/munged.pid.$$" &&
    mkdir -m 0755 -p "${MUNGE_PIDDIR}" &&

    : "${MUNGE_SEEDDIR:="${MUNGE_ROOT}/lib"}" &&
    MUNGE_SEEDFILE="${MUNGE_SEEDDIR}/munged.seed.$$" &&
    mkdir -m 0755 -p "${MUNGE_SEEDDIR}"
}

##
# Create the smallest-allowable key if one does not already exist.
##
munged_create_key()
{
    if test ! -r "${MUNGE_KEYFILE}"; then
        test_debug "echo \"${MUNGEKEY}\" \
                --create \
                --keyfile=\"${MUNGE_KEYFILE}\" \
                --bits=256" &&
        "${MUNGEKEY}" \
                --create \
                --keyfile="${MUNGE_KEYFILE}" \
                --bits=256
    fi
}

##
# Start munged, removing an existing logfile (from a previous run) if present.
# If the first arg matches "--exec=", its value will be used to exec munged.
# Additional arguments will be appended to the munged command-line.
##
munged_start_daemon()
{
    local EXEC &&
    if expr "$1" : "--exec=" >/dev/null; then
        EXEC=$(echo "$1" | sed "s/^[^=]*=//")
        shift
    fi &&
    rm -f "${MUNGE_LOGFILE}" &&
    test_debug "echo ${EXEC} \"${MUNGED}\" \
            --socket=\"${MUNGE_SOCKET}\" \
            --key-file=\"${MUNGE_KEYFILE}\" \
            --log-file=\"${MUNGE_LOGFILE}\" \
            --pid-file=\"${MUNGE_PIDFILE}\" \
            --seed-file=\"${MUNGE_SEEDFILE}\" \
            $*" &&
    ${EXEC} "${MUNGED}" \
            --socket="${MUNGE_SOCKET}" \
            --key-file="${MUNGE_KEYFILE}" \
            --log-file="${MUNGE_LOGFILE}" \
            --pid-file="${MUNGE_PIDFILE}" \
            --seed-file="${MUNGE_SEEDFILE}" \
            "$@"
}

##
# Stop munged.
# Additional arguments will be appended to the munged command-line.
##
munged_stop_daemon()
{
    test_debug "echo \"${MUNGED}\" \
            --socket=\"${MUNGE_SOCKET}\" \
            --stop \
            $*" &&
    "${MUNGED}" \
            --socket="${MUNGE_SOCKET}" \
            --stop \
            "$@"
}
