# Requires MUNGE_BUILD_DIR.

##
# Set paths to executables.
##
MUNGE="${MUNGE_BUILD_DIR}/src/munge/munge"
UNMUNGE="${MUNGE_BUILD_DIR}/src/munge/unmunge"
REMUNGE="${MUNGE_BUILD_DIR}/src/munge/remunge"
MUNGED="${MUNGE_BUILD_DIR}/src/munged/munged"
MUNGEKEY="${MUNGE_BUILD_DIR}/src/mungekey/mungekey"

##
# Require executables to be built before tests can proceed.
##
check_executables()
{
    local EXEC

    for EXEC in "${MUNGE}" "${UNMUNGE}" "${REMUNGE}" "${MUNGED}" "${MUNGEKEY}"
    do
        if test ! -x "${EXEC}"; then
            echo "ERROR: MUNGE has not been built: ${EXEC} not found."
            exit 1
        fi
    done
}

check_executables
