##
# Is non-interactive sudo available?
##
if sudo --non-interactive true >/dev/null 2>&1; then
    test_set_prereq SUDO
fi
