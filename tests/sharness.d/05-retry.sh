# Retry [$1] (command) up to [$2] (count) times.
# Return 0 on success, 1 on error, 2 on invalid count.
#
retry()
{
    retry_cnt="$1"
    retry_cmd="$2"
    retry_i=1

    test "${retry_cnt}" -gt 0 2>/dev/null || return 2

    while true; do
        test_debug 'echo "retry ${retry_i}/${retry_cnt}: ${retry_cmd}"'
        eval ${retry_cmd}
        test "$?" -eq 0 && return 0
        test "${retry_i}" -ge "${retry_cnt}" && return 1
        retry_i=$((retry_i + 1))
        sleep 1
    done
    return 3                            # not reached
}
