##
# Is non-interactive sudo available?
# Designate sudo-invoked commands as "expensive".  Enable them with the
#   sharness "--long-tests" option.  The EXPENSIVE prereq has not been set yet,
#   so check TEST_LONG instead.
##
if test "x${TEST_LONG}" != x && sudo -n true >/dev/null 2>&1; then
    test_set_prereq SUDO
fi
