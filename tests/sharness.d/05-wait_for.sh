# Wait for command $1 to succeed (rv 0) within timeout $2 seconds (default 5).
#   The command is executed every $3 seconds (default 0.1) until it succeeds
#   or the timeout is reached.
# Return 0 if command succeeds within the timeout, 1 if the timeout expires.
#
wait_for()
{
    _wf_cmd="$1"
    _wf_timeout_secs="${2:-5}"
    _wf_delay_secs="${3:-0.1}"
    _wf_count=$(awk "BEGIN {print int(${_wf_timeout_secs}/${_wf_delay_secs})}")

    while test "${_wf_count}" -gt 0; do
        eval "${_wf_cmd}" >/dev/null 2>&1 && return 0
        sleep "${_wf_delay_secs}"
        _wf_count=$((_wf_count - 1))
    done
    return 1
}
