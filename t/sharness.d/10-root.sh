##
# Is the test being run by the root user?
##
if test "$(id -u)" = 0; then
    test_set_prereq ROOT
fi
