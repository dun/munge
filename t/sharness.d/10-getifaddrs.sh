# Requires MUNGE_BUILD_DIR.

##
# Got HAVE_GETIFADDRS?
##
if egrep -q '^#define.*\<HAVE_GETIFADDRS\>.*1' \
        "${MUNGE_BUILD_DIR}/config.h" >/dev/null 2>&1; then
    test_set_prereq GETIFADDRS
fi
