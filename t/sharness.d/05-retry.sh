##
# Retry the COMMAND up to COUNT times.
# Return 0 on success, 1 on error, 2 on invalid COUNT.
##
retry()
{
    local COUNT="$1"
    local COMMAND="$2"
    local i=1

    test "${COUNT}" -gt 0 2>/dev/null || return 2

    while true; do
        test_debug 'echo "retry $i/${COUNT}: ${COMMAND}"'
        eval ${COMMAND}
        test "$?" -eq 0 && return 0
        test "$i" -ge "${COUNT}" && return 1
        i=$((i + 1))
        sleep 1
    done
    return 3                            # not reached
}
