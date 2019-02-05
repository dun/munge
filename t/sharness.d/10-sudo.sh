##
# Is non-interactive sudo available?
##
if sudo -n true >/dev/null 2>&1; then
    test_set_prereq SUDO
fi
