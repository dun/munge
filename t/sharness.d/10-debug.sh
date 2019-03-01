# Requires MUNGE_BUILD_DIR.

##
# Is debug enabled?
##
if egrep -q '^#define.*\<NDEBUG\>.*1' \
        "${MUNGE_BUILD_DIR}/config.h" >/dev/null 2>&1; then :; else
    test_set_prereq DEBUG
fi
