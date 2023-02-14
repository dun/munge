# Retry [command] up to [count] times.
# Return 0 on success, 1 on error, 2 on invalid [count].
#
retry()
{
    local count="$1"
    local command="$2"
    local i=1

    test "${count}" -gt 0 2>/dev/null || return 2

    while true; do
        test_debug 'echo "retry $i/${count}: ${command}"'
        eval ${command}
        test "$?" -eq 0 && return 0
        test "$i" -ge "${count}" && return 1
        i=$((i + 1))
        sleep 1
    done
    return 3                            # not reached
}
