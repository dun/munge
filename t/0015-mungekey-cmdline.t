#!/bin/sh

test_description='Check mungekey command-line options'

. "$(dirname "$0")/sharness.sh"

# Check if an invalid short-option displays the expected option text in the
#   error message.
##
test_expect_success 'mungekey invalid short option' '
    test_must_fail "${MUNGEKEY}" -9 2>err.$$ &&
    grep -q "Option \"-9\" is invalid" err.$$
'

# Check if an invalid long-option displays the expected option text in the
#   error message.
##
test_expect_success 'mungekey invalid long option' '
    test_must_fail "${MUNGEKEY}" --invalid-option 2>err.$$ &&
    grep -q "Option \"--invalid-option\" is invalid" err.$$
'

# Check if a non-printable option is handled.  This tests the case where the
#   text of an invalid option cannot be properly displayed.
##
test_expect_success 'mungekey invalid non-printable short option' '
    test_must_fail "${MUNGEKEY}" - 2>err.$$ &&
    grep -q "Failed to process command-line" err.$$
'

# Check if an unimplemented option is handled.
# The unimplemented short-option is specified in GETOPT_DEBUG_SHORT_OPTS
#   when configured with --enable-debug.
##
test_expect_success DEBUG 'mungekey unimplemented option' '
    test_must_fail "${MUNGEKEY}" -8 2>err.$$ &&
    grep -q "Option \"-8\" is not implemented" err.$$
'

# Check if a non-option option (i.e., one without a single or double leading
#   hyphen) is handled.  This tests the case of leftover args in argv[] after
#   getopt_long() is finished.
##
test_expect_success 'mungekey unrecognized option' '
    test_must_fail "${MUNGEKEY}" unrecognized-option 2>err.$$ &&
    grep -q "Option \"unrecognized-option\" is unrecognized" err.$$
'

# Check if a single lone hyphen is handled.
##
test_expect_success 'mungekey lone hyphen option' '
    test_must_fail "${MUNGEKEY}" - 2>err.$$ &&
    grep -q "Option \"-\" is unrecognized" err.$$
'

# Check for a successful exit after writing usage info to stdout.
##
for OPT_HELP in '-h' '--help'; do
    test_expect_success "mungekey ${OPT_HELP}" '
        "${MUNGEKEY}" "${OPT_HELP}" >out.$$ &&
        grep -q "^Usage:" out.$$
    '
done

# Check for a successful exit after writing license info to stdout.
##
for OPT_LICENSE in '-L' '--license'; do
    test_expect_success "mungekey ${OPT_LICENSE}" '
        "${MUNGEKEY}" "${OPT_LICENSE}" >out.$$ &&
        grep -q "GNU General Public License" out.$$
    '
done

# Check for a successful exit after writing version info to stdout.
##
for OPT_VERSION in '-V' '--version'; do
    test_expect_success "mungekey ${OPT_VERSION}" '
        "${MUNGEKEY}" "${OPT_VERSION}" >out.$$ &&
        grep -q "^munge-[0-9.]*" out.$$
    '
done

# Check if the keyfile is created and properly permissioned.
##
for OPT_CREATE in '-c' '--create'; do
    test_expect_success "mungekey ${OPT_CREATE}" '
        local KEYFILE=key.$$ &&
        rm -f "${KEYFILE}" &&
        test ! -f "${KEYFILE}" &&
        "${MUNGEKEY}" "${OPT_CREATE}" --keyfile="${KEYFILE}" &&
        test -f "${KEYFILE}" &&
        test "$(find ${KEYFILE} -perm 0600)" = "${KEYFILE}"
    '
done

# Check if the keyfile is the appropriate size based on the number of bits
#   specified.
##
for OPT_BITS in '-b' '--bits'; do
    test_expect_success "mungekey ${OPT_BITS}" '
        local KEYFILE=key.$$ NUM_BITS=1000 FILE_SIZE &&
        rm -f "${KEYFILE}" &&
        test ! -f "${KEYFILE}" &&
        "${MUNGEKEY}" --create --keyfile="${KEYFILE}" \
                "${OPT_BITS}" "${NUM_BITS}" &&
        test -f "${KEYFILE}" &&
        FILE_SIZE=$(wc -c < "${KEYFILE}") &&
        test "${FILE_SIZE}" -eq "$(( ${NUM_BITS} / 8 ))"
    '
done

# Check if the number of bits is rounded-up to the next byte if it is not
#   evenly divisible by 8.  NUM_BITS is set to 1 bit above the requested
#   NUM_BYTES.
##
test_expect_success 'mungekey --bits rounding-up to next byte' '
    local KEYFILE=key.$$ NUM_BYTES=128 NUM_BITS NUM_BYTES_ROUNDED FILE_SIZE &&
    NUM_BITS=$(( (${NUM_BYTES} * 8) + 1 )) &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --create --keyfile="${KEYFILE}" --bits="${NUM_BITS}" &&
    test -f "${KEYFILE}" &&
    NUM_BYTES_ROUNDED=$(( (${NUM_BITS} + 7) / 8 )) &&
    test "${NUM_BYTES_ROUNDED}" = "$(( ${NUM_BYTES} + 1 ))" &&
    FILE_SIZE=$(wc -c < "${KEYFILE}") &&
    test "${FILE_SIZE}" -eq "${NUM_BYTES_ROUNDED}"
'

# Check if the default def is used when the number of bits is unspecified.
##
test_expect_success 'mungekey --bits unspecified and using default' '
    local KEYFILE=key.$$ DEFS NUM_BYTES NUM_BITS FILE_SIZE &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_DFL_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( ${NUM_BYTES} * 8 )) &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --create --keyfile="${KEYFILE}" &&
    test -f "${KEYFILE}" &&
    FILE_SIZE=$(wc -c < "${KEYFILE}") &&
    test "${FILE_SIZE}" -eq "${NUM_BYTES}"
'

# Check the boundary case for the minimum number of bits.
##
test_expect_success 'mungekey --bits with minimum value' '
    local KEYFILE=key.$$ DEFS NUM_BYTES NUM_BITS FILE_SIZE &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_MIN_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( ${NUM_BYTES} * 8 )) &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --create --keyfile="${KEYFILE}" --bits="${NUM_BITS}" &&
    test -f "${KEYFILE}" &&
    FILE_SIZE=$(wc -c < "${KEYFILE}") &&
    test "${FILE_SIZE}" -eq "${NUM_BYTES}"
'

# Check the boundary case for the maximum number of bits.
##
test_expect_success 'mungekey --bits with maximum value' '
    local KEYFILE=key.$$ DEFS NUM_BYTES NUM_BITS FILE_SIZE &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_MAX_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( ${NUM_BYTES} * 8 )) &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --create --keyfile="${KEYFILE}" --bits="${NUM_BITS}" &&
    test -f "${KEYFILE}" &&
    FILE_SIZE=$(wc -c < "${KEYFILE}") &&
    test "${FILE_SIZE}" -eq "${NUM_BYTES}"
'

# Check the boundary case below the minimum number of bits.
##
test_expect_success 'mungekey --bits below minimum value' '
    local DEFS NUM_BYTES NUM_BITS &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_MIN_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( (${NUM_BYTES} * 8) - 1 )) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ \
            --bits="${NUM_BITS}" 2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value \"${NUM_BITS}\"" err.$$
'

# Check the boundary case above the maximum number of bits.
##
test_expect_success 'mungekey --bits above maximum value' '
    local DEFS NUM_BYTES NUM_BITS &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_MAX_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( (${NUM_BYTES} * 8) + 1 )) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ \
            --bits="${NUM_BITS}" 2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value \"${NUM_BITS}\"" err.$$
'

# Check if the minimum number of bits is displayed in the error message.
##
test_expect_success 'mungekey --bits error message with minimum value' '
    local DEFS NUM_BYTES NUM_BITS &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_MIN_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( ${NUM_BYTES} * 8 )) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=1 2>err.$$ &&
    grep -q -- "${NUM_BITS}-" err.$$
'

# Check if the maximum number of bits is displayed in the error message.
##
test_expect_success 'mungekey --bits error message with maximum value' '
    local DEFS NUM_BYTES NUM_BITS &&
    DEFS="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${DEFS}" &&
    NUM_BYTES=$(awk "/MUNGE_KEY_LEN_MAX_BYTES/ { print \$3 }" "${DEFS}") &&
    NUM_BITS=$(( ${NUM_BYTES} * 8 )) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=1 2>err.$$ &&
    grep -q -- "-${NUM_BITS}" err.$$
'

# Check the case for zero number of bits.
##
test_expect_success 'mungekey --bits with zero value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=0 2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value" err.$$
'

# Check the case for a negative number of bits.
##
test_expect_success 'mungekey --bits with negative value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=-1 \
            2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value" err.$$
'

# Check if -b requires an argument and displays the expected short-option text
#   in the error message.
##
test_expect_success 'mungekey -b without required value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ -b 2>err.$$ &&
    grep -q "Option \"-b\" is missing a required argument" err.$$
'

# Check if --bits requires an argument and displays the expected long-option
#   text in the error message.
##
test_expect_success 'mungekey --bits without required value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits 2>err.$$ &&
    grep -q "Option \"--bits\" is missing a required argument" err.$$
'

# Check if --force removes an existing keyfile.
##
for OPT_FORCE in '-f' '--force'; do
    test_expect_success "mungekey ${OPT_FORCE}" '
        local KEYFILE=key.$$ &&
        rm -f "${KEYFILE}" &&
        touch "${KEYFILE}" &&
        test ! -s "${KEYFILE}" &&
        "${MUNGEKEY}" --create --keyfile="${KEYFILE}" "${OPT_FORCE}" &&
        test -s "${KEYFILE}"
    '
done

# Check if the lack of --force preserves an existing and writable keyfile.
##
test_expect_success 'mungekey without --force and with existing keyfile' '
    local KEYFILE=key.$$ &&
    rm -f "${KEYFILE}" &&
    echo -n xyzzy-$$ > "${KEYFILE}" &&
    chmod 0600 "${KEYFILE}" &&
    test_must_fail "${MUNGEKEY}" --create --keyfile="${KEYFILE}" 2>err.$$ &&
    grep -q "File exists" err.$$ &&
    test "$(cat ${KEYFILE})" = xyzzy-$$
'

# Check if an alternate keyfile can be specified.
# This is tested by practically every testcase in order to prevent writing a
#   key somewhere it shouldn't.
##
for OPT_KEYFILE in '-k' '--keyfile'; do
    test_expect_success "mungekey ${OPT_KEYFILE}" '
        local KEYFILE=key.$$ &&
        rm -f "${KEYFILE}" &&
        test ! -f "${KEYFILE}" &&
        "${MUNGEKEY}" --create "${OPT_KEYFILE}" "${KEYFILE}" &&
        test -f "${KEYFILE}"
    '
done

# Check if -k requires an argument and displays the expected short-option text
#   in the error message.
##
test_expect_success 'mungekey -k without required value' '
    test_must_fail "${MUNGEKEY}" --create -k 2>err.$$ &&
    grep -q "Option \"-k\" is missing a required argument" err.$$
'

# Check if --keyfile requires an argument and displays the expected long-option
#   text in the error message.
##
test_expect_success 'mungekey --keyfile without required value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile 2>err.$$ &&
    grep -q "Option \"--keyfile\" is missing a required argument" err.$$
'

# Check if an informational message is written to stderr when creating a key
#   with --verbose.
##
for OPT_VERBOSE in '-v' '--verbose'; do
    test_expect_success "mungekey ${OPT_VERBOSE}" '
        local KEYFILE=key.$$ &&
        rm -f "${KEYFILE}" &&
        test ! -f "${KEYFILE}" &&
        "${MUNGEKEY}" --create --keyfile="${KEYFILE}" "${OPT_VERBOSE}" \
                2>err.$$ &&
        test -f "${KEYFILE}" &&
        grep -q "Created \"${KEYFILE}\"" err.$$
    '
done

# Check if the informational message written to stderr when creating a key
#   contains the number of bits used.
##
test_expect_success 'mungekey --verbose number of bits' '
    local KEYFILE=key.$$ NUM_BITS=1000 NUM_BITS_USED &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --create --keyfile="${KEYFILE}" --bits="${NUM_BITS}" \
            --verbose 2>err.$$ &&
    test -f "${KEYFILE}" &&
    NUM_BITS_USED=$(sed -n -e "s/.* \([0-9][0-9]*\)-bit.*/\\1/p" err.$$) &&
    test "${NUM_BITS_USED}" -eq "${NUM_BITS}"
'

# Check that nothing is written to stdout or stderr when successfully creating
#   a key without --verbose (unless configured with --enable-debug).
##
test_expect_success !DEBUG 'mungekey without --verbose' '
    local KEYFILE=key.$$ &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --create --keyfile="${KEYFILE}" >out.$$ 2>err.$$ &&
    test -f "${KEYFILE}" &&
    test ! -s out.$$ &&
    test ! -s err.$$
'

# With getopt_long(), long_ind is only set when a long-option is successfully
#   parsed.  It must be re-initialized before each call to getopt_long().
#   If not, it may erroneously refer to a previous option.
# Check if long_ind is being re-initialized by specifying the --keyfile
#   long-option (and required argument) followed by the -b short-option
#   (with an invalid value to trigger the error case).  If long_ind is not
#   being re-initialized, the error message will erroneously refer to the last
#   successfully-parsed long-option (i.e., --keyfile).
##
test_expect_success 'mungekey long_ind re-initialized for getopt_long()' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ -b 1 2>err.$$ &&
    grep -q "Option \"-b\" has invalid value" err.$$
'

# Check if mungekey defaults to creating a key if no operation is specified.
#   The --keyfile option does not specify an operation, and it must be
#   specified here to prevent writing a key somewhere it shouldn't.
##
test_expect_success 'mungekey defaults to create key' '
    local KEYFILE=key.$$ &&
    rm -f "${KEYFILE}" &&
    test ! -f "${KEYFILE}" &&
    "${MUNGEKEY}" --keyfile="${KEYFILE}" &&
    test -f "${KEYFILE}"
'

test_done
