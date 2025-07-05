# [MUNGE_BUILD_DIR] is set in "01-directories.sh".

# Set paths to executables.
#
MUNGE="${MUNGE_BUILD_DIR}/src/munge/munge"
UNMUNGE="${MUNGE_BUILD_DIR}/src/munge/unmunge"
REMUNGE="${MUNGE_BUILD_DIR}/src/munge/remunge"
MUNGED="${MUNGE_BUILD_DIR}/src/munged/munged"
MUNGEKEY="${MUNGE_BUILD_DIR}/src/mungekey/mungekey"

# Require executables to be built before tests can proceed.
#
set_executables()
{
    for _cmd in "${MUNGE}" "${UNMUNGE}" "${REMUNGE}" "${MUNGED}" "${MUNGEKEY}"
    do
        if test ! -x "${_cmd}"; then
            echo "ERROR: MUNGE has not been built: ${_cmd} not found."
            exit 1
        fi
    done
}

set_executables
