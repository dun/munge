# Search from directory [$1] on up to root, looking for the directory that
#   contains [$2].
# Output the resulting directory if a match is found.
#
search_dirs()
{
    local start_dir=$1
    local target_file=$2
    (
        cd "${start_dir}" &&
        while test "$(pwd)" != "/"; do
            test -e "${target_file}" && pwd && break
            cd ..
        done
    )
}

# Set the top-level build directory.
#
set_build_dir()
{
    MUNGE_BUILD_DIR=$(search_dirs "." "config.status")
    if test -z "${MUNGE_BUILD_DIR}"; then
        echo "ERROR: Failed to set MUNGE_BUILD_DIR: not configured"
        exit 1
    fi
}

# Set the top-level source directory.
#
set_source_dir()
{
    MUNGE_SOURCE_DIR=$(search_dirs \
            $(dirname "${SHARNESS_TEST_FILE}") "configure.ac")
    if test -z "${MUNGE_SOURCE_DIR}"; then
        echo "ERROR: Failed to set MUNGE_SOURCE_DIR: cannot locate source"
        exit 1
    fi
}

set_build_dir
set_source_dir
