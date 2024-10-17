# Is faketime installed?
#
if faketime --help >/dev/null 2>&1; then
    test_set_prereq FAKETIME
fi
