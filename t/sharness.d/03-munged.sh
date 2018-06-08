# Requires MUNGED and MUNGEKEY.

##
# Create smallest-allowable key [$1] for munged if it does not already exist.
##
munged_create_key()
{
    local KEY=$1 &&
    if test ! -r "${KEY}"; then
        "${MUNGEKEY}" --create --keyfile="${KEY}" --bits=256
    fi
}

##
# Start munged and set env vars.
# The socket is placed in TMPDIR since NFS can cause problems for the lockfile.
#   Debian 3.1 returns an incorrect PID for the process holding the lock across
#   an NFS mount.  FreeBSD cannot create a lockfile across an NFS mount.
# The first argument (if specified) is used to exec the daemon
#   (e.g., for running under valgrind and passing in its options).
# Additional arguments will be appended to the munged command-line options.
##
munged_start_daemon()
{
    local EXEC MASK=$(umask) SOCKET KEYFILE LOGFILE PIDFILE SEEDFILE &&
    if test $# -gt 0; then
        EXEC=$1
        shift
    fi &&
    SOCKET="${TMPDIR:-"/tmp"}/munged.sock.$$" &&
    KEYFILE="munged.key.$$" &&
    LOGFILE="munged.log.$$" &&
    PIDFILE="munged.pid.$$" &&
    SEEDFILE="munged.seed.$$" &&
    umask 022 &&
    munged_create_key "${KEYFILE}" &&
    ${EXEC} "${MUNGED}" \
        --socket="${SOCKET}" \
        --key-file="$(pwd)/${KEYFILE}" \
        --log-file="$(pwd)/${LOGFILE}" \
        --pid-file="$(pwd)/${PIDFILE}" \
        --seed-file="$(pwd)/${SEEDFILE}" \
        "$@" &&
    umask "${MASK}" &&
    MUNGE_PIDFILE="${PIDFILE}" &&
    MUNGE_SOCKET="${SOCKET}"
}

##
# Stop munged and clear env vars.
##
munged_stop_daemon()
{
    "${MUNGED}" --stop --socket="${MUNGE_SOCKET}" &&
    unset MUNGE_SOCKET &&
    unset MUNGE_PIDFILE
}
