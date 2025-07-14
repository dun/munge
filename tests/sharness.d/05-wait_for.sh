# Wait for command $1 to succeed (rv 0) within timeout $2 seconds (default 5).
#   The command is executed every $3 seconds (default 0.1) until it succeeds or
#   the timeout is reached.
# Return 0 if the command succeeds within the timeout, 1 if timeout expires.
#
wait_for()
{
    _wf_cmd="$1"
    _wf_secs="${2:-5}"
    _wf_delay="${3:-0.1}"
    _wf_cnt=$(awk "BEGIN {print int(${_wf_secs} / ${_wf_delay})}")

    while test "${_wf_cnt}" -gt 0; do
        eval "${_wf_cmd}" && return 0
        sleep "${_wf_delay}"
        _wf_cnt=$((_wf_cnt - 1))
    done
    return 1
}
