# Is valgrind installed?
# Require 3.10.0 or later.
#
VALGRIND_VERSION=$(valgrind --version 2>/dev/null)
if test "$?" -eq 0; then
    _major=$(echo "${VALGRIND_VERSION}" | sed -ne 's/[^-]*-\([0-9]*\).*/\1/p')
    _minor=$(echo "${VALGRIND_VERSION}" | sed -ne 's/[^.]*.\([0-9]*\).*/\1/p')
    if { test "${_major}" -eq 3 && test "${_minor}" -ge 10; } || \
       { test "${_major}" -gt 3; }; then
        test_set_prereq VALGRIND
    fi
fi

# Set the name of the valgrind log file.
#
VALGRIND_LOGFILE="valgrind.log.$$"

# Valgrind command (executed via libtool) and options for memcheck analysis.
# This allows the program being analyzed to be run in the background.
#   Results of the valgrind analysis are checked via valgrind_check_log().
# Use of this variable should be followed by the program being analyzed
#   along with any of its command-line options.
#
VALGRIND_CMD="libtool --mode=execute valgrind --tool=memcheck \
    --errors-for-leak-kinds=all \
    --gen-suppressions=all \
    --keep-stacktraces=alloc-and-free \
    --leak-check=full \
    --leak-resolution=high \
    --log-file=${VALGRIND_LOGFILE} \
    --num-callers=40 \
    --partial-loads-ok=no \
    --read-var-info=yes \
    --show-leak-kinds=all \
    --suppressions=${SHARNESS_TEST_SRCDIR}/valgrind.supp \
    --track-origins=yes \
    --undef-value-errors=yes \
"

# Check the valgrind log for errors.
# Output the log file if errors are found or if debugging is enabled.
#
valgrind_check_log()
{
    if test ! -s "${VALGRIND_LOGFILE}"; then
        echo "ERROR: Valgrind logfile [${VALGRIND_LOGFILE}] not found."
        _rv=1
    elif grep -q 'ERROR SUMMARY: [^0]' "${VALGRIND_LOGFILE}"; then
        cat "${VALGRIND_LOGFILE}"
        _rv=1
    else
        test_debug 'cat "${VALGRIND_LOGFILE}"'
        _rv=0
    fi
    return ${_rv}
}
