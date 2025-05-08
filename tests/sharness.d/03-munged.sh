# Set up the directory tree and shell variables for starting munged.
# [MUNGE_ROOT], [MUNGE_SOCKETDIR], [MUNGE_KEYDIR], [MUNGE_LOGDIR],
#   [MUNGE_PIDDIR], and [MUNGE_SEEDDIR] can be overridden by setting them
#   beforehand.
# [MUNGE_SOCKET] is placed in [TMPDIR] by default since NFS can cause problems
#   for the lockfile.  Debian 3.1 returns an incorrect pid for the process
#   holding the lock across an NFS mount.  FreeBSD cannot create a lockfile
#   across an NFS mount.
# Provides [MUNGE_SOCKET], [MUNGE_KEYFILE], [MUNGE_LOGFILE], [MUNGE_PIDFILE],
#   and [MUNGE_SEEDFILE].
#
munged_setup()
{
    umask 0022

    : "${MUNGE_ROOT:="$(pwd)"}"
    mkdir -m 0755 -p "${MUNGE_ROOT}"

    : "${MUNGE_SOCKETDIR:="${TMPDIR:-"/tmp"}"}"
    MUNGE_SOCKET="${MUNGE_SOCKETDIR}/munged.sock.$$"
    mkdir -m 1777 -p "${MUNGE_SOCKETDIR}"
    test_debug "echo MUNGE_SOCKET=\"${MUNGE_SOCKET}\""

    : "${MUNGE_KEYDIR:="${MUNGE_ROOT}/etc-$$"}"
    MUNGE_KEYFILE="${MUNGE_KEYDIR}/munged.key.$$"
    mkdir -m 0755 -p "${MUNGE_KEYDIR}"
    test_debug "echo MUNGE_KEYFILE=\"${MUNGE_KEYFILE}\""

    : "${MUNGE_LOGDIR:="${MUNGE_ROOT}/log-$$"}"
    MUNGE_LOGFILE="${MUNGE_LOGDIR}/munged.log.$$"
    mkdir -m 0755 -p "${MUNGE_LOGDIR}"
    test_debug "echo MUNGE_LOGFILE=\"${MUNGE_LOGFILE}\""

    : "${MUNGE_PIDDIR:="${MUNGE_ROOT}/run-$$"}"
    MUNGE_PIDFILE="${MUNGE_PIDDIR}/munged.pid.$$"
    mkdir -m 0755 -p "${MUNGE_PIDDIR}"
    test_debug "echo MUNGE_PIDFILE=\"${MUNGE_PIDFILE}\""

    : "${MUNGE_SEEDDIR:="${MUNGE_ROOT}/lib-$$"}"
    MUNGE_SEEDFILE="${MUNGE_SEEDDIR}/munged.seed.$$"
    mkdir -m 0755 -p "${MUNGE_SEEDDIR}"
    test_debug "echo MUNGE_SEEDFILE=\"${MUNGE_SEEDFILE}\""
}

# Create the smallest-allowable key if one does not already exist.
# The following leading args are recognized:
#   t-bail-out-on-error - bail out if mungekey fails.
#   t-exec=ARG - use ARG to exec mungekey.
# Remaining args will be appended to the mungekey command-line.
# When using t-bail-out-on-error, munged_create_key should be at the start of
#   the &&-chain to ensure Bail Out will occur on error.
#
munged_create_key()
{
    local can_bail_out= exec= rv=0

    while true; do
        case $1 in
            t-bail-out-on-error) can_bail_out=1;;
            t-exec=*) exec=$(echo "$1" | sed 's/^[^=]*=//');;
            *) break;;
        esac
        shift
    done

    if test ! -r "${MUNGE_KEYFILE}"; then
        test_debug "echo ${exec} \"${MUNGEKEY}\" \
                --create \
                --keyfile=\"${MUNGE_KEYFILE}\" \
                --bits=256 \
                $*"
        ${exec} "${MUNGEKEY}" \
                --create \
                --keyfile="${MUNGE_KEYFILE}" \
                --bits=256 \
                "$@"
        rv=$?
        if test "${rv}" -ne 0 && test "${can_bail_out}" = 1; then
            bail_out "Failed to create key"
        fi
    fi
    return ${rv}
}

# Start munged, removing an existing logfile or killing an errant munged
#   process (from a previous run) if needed.
# The following leading args are recognized:
#   t-bail-out-on-error - bail out if munged fails.
#   t-exec=ARG - use ARG to exec munged.
#   t-keep-logfile - do not remove logfile before starting munged.
#   t-keep-process - do not kill previous munged process.
# Remaining args will be appended to the munged command-line.
# When using t-bail-out-on-error, munged_start should be at the start of
#   the &&-chain to ensure Bail Out will occur on error.
#
munged_start()
{
    local can_bail_out= exec= keep_logfile= keep_process= rv=0

    while true; do
        case $1 in
            t-bail-out-on-error) can_bail_out=1;;
            t-exec=*) exec=$(echo "$1" | sed 's/^[^=]*=//');;
            t-keep-logfile) keep_logfile=1;;
            t-keep-process) keep_process=1;;
            *) break;;
        esac
        shift
    done

    if test "${keep_logfile}" != 1; then
        rm -f "${MUNGE_LOGFILE}"
    fi
    if test "${keep_process}" != 1; then
        munged_kill
    fi
    test_debug "echo ${exec} \"${MUNGED}\" \
            --socket=\"${MUNGE_SOCKET}\" \
            --key-file=\"${MUNGE_KEYFILE}\" \
            --log-file=\"${MUNGE_LOGFILE}\" \
            --pid-file=\"${MUNGE_PIDFILE}\" \
            --seed-file=\"${MUNGE_SEEDFILE}\" \
            --group-update-time=-1 \
            $*"
    ${exec} "${MUNGED}" \
            --socket="${MUNGE_SOCKET}" \
            --key-file="${MUNGE_KEYFILE}" \
            --log-file="${MUNGE_LOGFILE}" \
            --pid-file="${MUNGE_PIDFILE}" \
            --seed-file="${MUNGE_SEEDFILE}" \
            --group-update-time=-1 \
            "$@"
    rv=$?
    if test "${rv}" -ne 0 && test "${can_bail_out}" = 1; then
        bail_out "Failed to start munged"
    fi
    return ${rv}
}

# Stop munged.
# The following leading args are recognized:
#   t-exec=ARG - use ARG to exec munged.
# Remaining args will be appended to the munged command-line.
#
munged_stop()
{
    local exec=

    while true; do
        case $1 in
            t-exec=*) exec=$(echo "$1" | sed 's/^[^=]*=//');;
            *) break;;
        esac
        shift
    done

    test_debug "echo ${exec} \"${MUNGED}\" \
            --socket=\"${MUNGE_SOCKET}\" \
            --stop \
            --verbose \
            $*"
    ${exec} "${MUNGED}" \
            --socket="${MUNGE_SOCKET}" \
            --stop \
            --verbose \
            "$@"
}

# Kill an errant munged process from a previous test that is still running in
#   the background.  This situation is most likely to occur if a test starting
#   munged is expected to fail and instead erroneously succeeds.
# Only check for the pid named in [MUNGE_PIDFILE] to avoid interfering with
#   munged processes belonging to other tests or system use.  And check that
#   the named pid is a munged process and not one recycled by the system for
#   some other running process.
# A SIGKILL is sent instead of SIGTERM in case the signal handler has a bug
#   preventing graceful termination.  Since SIGKILL prevents the process from
#   cleaning up after itself, that cleanup must be performed here afterwards.
# The rm of the [MUNGE_SOCKET] glob also matches the corresponding lockfile.
#
munged_kill()
{
    local pid
    pid=$(cat "${MUNGE_PIDFILE}" 2>/dev/null)
    if test "x${pid}" != x; then
        if ps -p "${pid}" -ww 2>/dev/null | grep munged; then
            kill -9 "${pid}"
            echo "WARNING: Killed errant munged pid ${pid}"
        else
            echo "WARNING: Found stale pidfile for munged pid ${pid}"
        fi
        rm -f "${MUNGE_PIDFILE}" "${MUNGE_SOCKET}"*
    fi
}

# Perform housekeeping to clean up after munged.
# This should be called at the end of any test script that starts a munged
#   process.  It must be at the start of any &&-chain to ensure it cannot be
#   prevented from running by a preceding failure in the chain.
#
munged_cleanup()
{
    munged_kill
}
