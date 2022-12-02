#!/bin/sh

test_description='Check mungekey command-line options'

: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Check if an invalid short-option displays the expected option text in the
#   error message.
#
test_expect_success 'mungekey invalid short option' '
    test_must_fail "${MUNGEKEY}" -9 2>err.$$ &&
    grep -q "Option \"-9\" is invalid" err.$$
'

# Check if an invalid long-option displays the expected option text in the
#   error message.
#
test_expect_success 'mungekey invalid long option' '
    test_must_fail "${MUNGEKEY}" --invalid-option 2>err.$$ &&
    grep -q "Option \"--invalid-option\" is invalid" err.$$
'

# Check if a non-printable option is handled.  This tests the case where the
#   text of an invalid option cannot be properly displayed.
#
test_expect_success 'mungekey invalid non-printable short option' '
    test_must_fail "${MUNGEKEY}" - 2>err.$$ &&
    grep -q "Failed to process command-line" err.$$
'

# Check if an unimplemented option is handled.
# The unimplemented short-option is specified in GETOPT_DEBUG_SHORT_OPTS
#   when configured with --enable-debug.
#
test_expect_success DEBUG 'mungekey unimplemented option' '
    test_must_fail "${MUNGEKEY}" -8 2>err.$$ &&
    grep -q "Option \"-8\" is not implemented" err.$$
'

# Check if a non-option option (i.e., one without a single or double leading
#   hyphen) is handled.  This tests the case of leftover args in argv[] after
#   getopt_long() is finished.
#
test_expect_success 'mungekey unrecognized option' '
    test_must_fail "${MUNGEKEY}" unrecognized-option 2>err.$$ &&
    grep -q "Option \"unrecognized-option\" is unrecognized" err.$$
'

# Check if a single lone hyphen is handled.
#
test_expect_success 'mungekey lone hyphen option' '
    test_must_fail "${MUNGEKEY}" - 2>err.$$ &&
    grep -q "Option \"-\" is unrecognized" err.$$
'

# Check if usage information is written to stdout.
#
for OPT_HELP in '-h' '--help'; do
    test_expect_success "mungekey ${OPT_HELP}" '
        "${MUNGEKEY}" "${OPT_HELP}" |
        grep -q "^Usage:"
    '
done

# Check if license information is written to stdout.
#
for OPT_LICENSE in '-L' '--license'; do
    test_expect_success "mungekey ${OPT_LICENSE}" '
        "${MUNGEKEY}" "${OPT_LICENSE}" |
        grep -q "GNU General Public License"
    '
done

# Check if version information is written to stdout.
#
for OPT_VERSION in '-V' '--version'; do
    test_expect_success "mungekey ${OPT_VERSION}" '
        "${MUNGEKEY}" "${OPT_VERSION}" |
        grep -q "^munge-[0-9][0-9a-f.]* "
    '
done

# Check if the keyfile is created and properly permissioned.
#
for OPT_CREATE in '-c' '--create'; do
    test_expect_success "mungekey ${OPT_CREATE}" '
        local keyfile=key.$$ &&
        rm -f "${keyfile}" &&
        test ! -f "${keyfile}" &&
        "${MUNGEKEY}" "${OPT_CREATE}" --keyfile="${keyfile}" &&
        test -f "${keyfile}" &&
        test "$(find ${keyfile} -perm 0600)" = "${keyfile}"
    '
done

# Check if the keyfile is the appropriate size based on the number of bits
#   specified.
#
for OPT_BITS in '-b' '--bits'; do
    test_expect_success "mungekey ${OPT_BITS}" '
        local keyfile=key.$$ num_bits=1000 file_size &&
        rm -f "${keyfile}" &&
        test ! -f "${keyfile}" &&
        "${MUNGEKEY}" --create --keyfile="${keyfile}" \
                "${OPT_BITS}" "${num_bits}" &&
        test -f "${keyfile}" &&
        file_size=$(wc -c < "${keyfile}") &&
        test "${file_size}" -eq "$((num_bits / 8))"
    '
done

# Check if the number of bits is rounded-up to the next byte if it is not
#   evenly divisible by 8.  [num_bits] is set to 1 bit above the requested
#   [num_bytes].
#
test_expect_success 'mungekey --bits rounding-up to next byte' '
    local keyfile=key.$$ num_bytes=128 num_bits num_bytes_rounded file_size &&
    num_bits=$(((num_bytes * 8) + 1)) &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --create --keyfile="${keyfile}" --bits="${num_bits}" &&
    test -f "${keyfile}" &&
    num_bytes_rounded=$(((num_bits + 7) / 8)) &&
    test "${num_bytes_rounded}" = "$((num_bytes + 1))" &&
    file_size=$(wc -c < "${keyfile}") &&
    test "${file_size}" -eq "${num_bytes_rounded}"
'

# Check if the default def is used when the number of bits is unspecified.
#
test_expect_success 'mungekey --bits unspecified and using default' '
    local keyfile=key.$$ defs num_bytes num_bits file_size &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_DFL_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$((num_bytes * 8)) &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --create --keyfile="${keyfile}" &&
    test -f "${keyfile}" &&
    file_size=$(wc -c < "${keyfile}") &&
    test "${file_size}" -eq "${num_bytes}"
'

# Check the boundary case for the minimum number of bits.
#
test_expect_success 'mungekey --bits with minimum value' '
    local keyfile=key.$$ defs num_bytes num_bits file_size &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_MIN_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$((num_bytes * 8)) &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --create --keyfile="${keyfile}" --bits="${num_bits}" &&
    test -f "${keyfile}" &&
    file_size=$(wc -c < "${keyfile}") &&
    test "${file_size}" -eq "${num_bytes}"
'

# Check the boundary case for the maximum number of bits.
#
test_expect_success 'mungekey --bits with maximum value' '
    local keyfile=key.$$ defs num_bytes num_bits file_size &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_MAX_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$((num_bytes * 8)) &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --create --keyfile="${keyfile}" --bits="${num_bits}" &&
    test -f "${keyfile}" &&
    file_size=$(wc -c < "${keyfile}") &&
    test "${file_size}" -eq "${num_bytes}"
'

# Check the boundary case below the minimum number of bits.
#
test_expect_success 'mungekey --bits below minimum value' '
    local defs num_bytes num_bits &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_MIN_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$(((num_bytes * 8) - 1)) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ \
            --bits="${num_bits}" 2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value \"${num_bits}\"" err.$$
'

# Check the boundary case above the maximum number of bits.
#
test_expect_success 'mungekey --bits above maximum value' '
    local defs num_bytes num_bits &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_MAX_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$(((num_bytes * 8) + 1)) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ \
            --bits="${num_bits}" 2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value \"${num_bits}\"" err.$$
'

# Check if the minimum number of bits is displayed in the error message.
#
test_expect_success 'mungekey --bits error message with minimum value' '
    local defs num_bytes num_bits &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_MIN_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$((num_bytes * 8)) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=1 2>err.$$ &&
    grep -q -- "${num_bits}-" err.$$
'

# Check if the maximum number of bits is displayed in the error message.
#
test_expect_success 'mungekey --bits error message with maximum value' '
    local defs num_bytes num_bits &&
    defs="${MUNGE_SOURCE_DIR}/src/libcommon/munge_defs.h" &&
    test -f "${defs}" &&
    num_bytes=$(awk "/MUNGE_KEY_LEN_MAX_BYTES/ { print \$3 }" "${defs}") &&
    num_bits=$((num_bytes * 8)) &&
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=1 2>err.$$ &&
    grep -q -- "-${num_bits}" err.$$
'

# Check the case for zero number of bits.
#
test_expect_success 'mungekey --bits with zero value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=0 2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value" err.$$
'

# Check the case for a negative number of bits.
#
test_expect_success 'mungekey --bits with negative value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits=-1 \
            2>err.$$ &&
    grep -q "Option \"--bits\" has invalid value" err.$$
'

# Check if -b requires an argument and displays the expected short-option text
#   in the error message.
#
test_expect_success 'mungekey -b without required value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ -b 2>err.$$ &&
    grep -q "Option \"-b\" is missing a required argument" err.$$
'

# Check if --bits requires an argument and displays the expected long-option
#   text in the error message.
#
test_expect_success 'mungekey --bits without required value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ --bits 2>err.$$ &&
    grep -q "Option \"--bits\" is missing a required argument" err.$$
'

# Check if --force removes an existing keyfile.
#
for OPT_FORCE in '-f' '--force'; do
    test_expect_success "mungekey ${OPT_FORCE}" '
        local keyfile=key.$$ &&
        rm -f "${keyfile}" &&
        touch "${keyfile}" &&
        test ! -s "${keyfile}" &&
        "${MUNGEKEY}" --create --keyfile="${keyfile}" "${OPT_FORCE}" &&
        test -s "${keyfile}"
    '
done

# Check if the lack of --force preserves an existing and writable keyfile.
#
test_expect_success 'mungekey without --force and with existing keyfile' '
    local keyfile=key.$$ &&
    rm -f "${keyfile}" &&
    echo -n xyzzy-$$ > "${keyfile}" &&
    chmod 0600 "${keyfile}" &&
    test_must_fail "${MUNGEKEY}" --create --keyfile="${keyfile}" 2>err.$$ &&
    grep -q "File exists" err.$$ &&
    test "$(cat ${keyfile})" = xyzzy-$$
'

# Check if an alternate keyfile can be specified.
# This is tested by practically every testcase in order to prevent writing a
#   key somewhere it shouldn't.
#
for OPT_KEYFILE in '-k' '--keyfile'; do
    test_expect_success "mungekey ${OPT_KEYFILE}" '
        local keyfile=key.$$ &&
        rm -f "${keyfile}" &&
        test ! -f "${keyfile}" &&
        "${MUNGEKEY}" --create "${OPT_KEYFILE}" "${keyfile}" &&
        test -f "${keyfile}"
    '
done

# Check if -k requires an argument and displays the expected short-option text
#   in the error message.
#
test_expect_success 'mungekey -k without required value' '
    test_must_fail "${MUNGEKEY}" --create -k 2>err.$$ &&
    grep -q "Option \"-k\" is missing a required argument" err.$$
'

# Check if --keyfile requires an argument and displays the expected long-option
#   text in the error message.
#
test_expect_success 'mungekey --keyfile without required value' '
    test_must_fail "${MUNGEKEY}" --create --keyfile 2>err.$$ &&
    grep -q "Option \"--keyfile\" is missing a required argument" err.$$
'

# Check if an informational message is written to stderr when creating a key
#   with --verbose.
#
for OPT_VERBOSE in '-v' '--verbose'; do
    test_expect_success "mungekey ${OPT_VERBOSE}" '
        local keyfile=key.$$ &&
        rm -f "${keyfile}" &&
        test ! -f "${keyfile}" &&
        "${MUNGEKEY}" --create --keyfile="${keyfile}" "${OPT_VERBOSE}" \
                2>err.$$ &&
        test -f "${keyfile}" &&
        grep -q "Created \"${keyfile}\"" err.$$
    '
done

# Check if the informational message written to stderr when creating a key
#   contains the number of bits used.
#
test_expect_success 'mungekey --verbose number of bits' '
    local keyfile=key.$$ num_bits=1000 num_bits_used &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --create --keyfile="${keyfile}" --bits="${num_bits}" \
            --verbose 2>err.$$ &&
    test -f "${keyfile}" &&
    num_bits_used=$(sed -n -e "s/.* \([0-9][0-9]*\)-bit.*/\\1/p" err.$$) &&
    test "${num_bits_used}" -eq "${num_bits}"
'

# Check that nothing is written to stdout or stderr when successfully creating
#   a key without --verbose (unless configured with --enable-debug).
#
test_expect_success !DEBUG 'mungekey without --verbose' '
    local keyfile=key.$$ &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --create --keyfile="${keyfile}" >out.$$ 2>err.$$ &&
    test -f "${keyfile}" &&
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
#
test_expect_success 'mungekey long_ind re-initialized for getopt_long()' '
    test_must_fail "${MUNGEKEY}" --create --keyfile=key.$$ -b 1 2>err.$$ &&
    grep -q "Option \"-b\" has invalid value" err.$$
'

# Check if mungekey defaults to creating a key if no operation is specified.
#   The --keyfile option does not specify an operation, and it must be
#   specified here to prevent writing a key somewhere it shouldn't.
#
test_expect_success 'mungekey defaults to create key' '
    local keyfile=key.$$ &&
    rm -f "${keyfile}" &&
    test ! -f "${keyfile}" &&
    "${MUNGEKEY}" --keyfile="${keyfile}" &&
    test -f "${keyfile}"
'

test_done
