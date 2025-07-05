# Immediately bail out of the test script with the reason given in [$1].
# See <https://testanything.org/tap-specification.html>.

bail_out()
{
    bail_out_cmd="Bail out!"
    bail_out_msg="$1"
    say_color >&5 error "${bail_out_cmd}" "${bail_out_msg}"
    EXIT_OK=t
    exit 1
}
