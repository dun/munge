# Immediately bail out of the test script with the reason given in $1.
# See <https://testanything.org/tap-specification.html>.

bail_out()
{
    local bail_out="Bail out!"
    local message="$1"
    say_color >&5 error "${bail_out}" "${message}"
    EXIT_OK=t
    exit 1
}
