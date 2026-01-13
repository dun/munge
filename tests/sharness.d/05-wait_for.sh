# Wait for command $1 to succeed within $2 seconds (default 5).
#   The command is executed every $3 seconds (default 0.1) until success
#   (exit status 0) or the timeout is reached.
# Return 0 if command succeeds within the timeout, 1 if the timeout expires.
#
wait_for()
{
    local cmd timeout_secs delay_secs count
    cmd="$1"
    timeout_secs="${2:-5}"
    delay_secs="${3:-0.1}"
    count=$(awk "BEGIN {print int(${timeout_secs}/${delay_secs})}")

    while test "${count}" -gt 0; do
        eval "${cmd}" >/dev/null 2>&1 && return 0
        sleep "${delay_secs}"
        count=$((count - 1))
    done
    return 1
}
