# Retry command [$1] up to count [$2] times.
# Return 0 on success, 1 on error, 2 on invalid count.
#
retry()
{
    _count="$1"
    _cmd="$2"
    _i=1

    test "${_count}" -gt 0 2>/dev/null || return 2

    while true; do
        test_debug 'echo "retry ${_i}/${_count}: ${_cmd}"'
        eval ${_cmd}
        test "$?" -eq 0 && return 0
        test "${_i}" -ge "${_count}" && return 1
        _i=$((_i + 1))
        sleep 1
    done
    return 3                            # not reached
}
