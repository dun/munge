# [MUNGE_BUILD_DIR] is set in "01-directories.sh".

# Is debug enabled?
#
if ! grep -q '^#define.* NDEBUG .*1' "${MUNGE_BUILD_DIR}/config.h"; then
    test_set_prereq DEBUG
fi
