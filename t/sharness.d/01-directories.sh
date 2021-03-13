##
# Search from directory [$1] on up to root, looking for the directory that
#   contains [$2].
# Output the resulting directory if a match is found.
##
search_dirs()
{
    local START_DIR=$1
    local FIND_FILE=$2
    (
        cd "${START_DIR}" &&
        while test "$(pwd)" != "/"; do
            test -e "${FIND_FILE}" && pwd && break
            cd ..
        done
    )
}

##
# Set the top-level build directory.
##
set_build_dir()
{
    if test -z "${MUNGE_BUILD_DIR}"; then

        if test "x${builddir}" != x; then
            MUNGE_BUILD_DIR=${builddir}
        else
            MUNGE_BUILD_DIR=$(search_dirs "." "config.status")
        fi

        if test -z "${MUNGE_BUILD_DIR}"; then
            echo "ERROR: MUNGE has not been configured."
            exit 1
        fi

        export MUNGE_BUILD_DIR
    fi
}

##
# Set the top-level source directory.
##
set_source_dir()
{
    local DIR

    if test -z "${MUNGE_SOURCE_DIR}"; then

        DIR=$(dirname "${SHARNESS_TEST_FILE}")
        MUNGE_SOURCE_DIR=$(search_dirs "${DIR}" "configure.ac")

        if test -z "${MUNGE_SOURCE_DIR}"; then
            echo "ERROR: Failed to locate source directory."
            exit 1
        fi

        export MUNGE_SOURCE_DIR
    fi
}

set_build_dir
set_source_dir
