# Immediately bail out of the test script with the reason given in [$1].
# See <https://testanything.org/tap-specification.html>.

bail_out()
{
    _bail_out_cmd="Bail out!"
    _bail_out_msg="$1"
    say_color >&5 error "${_bail_out_cmd}" "${_bail_out_msg}"
    EXIT_OK=t
    exit 1
}
