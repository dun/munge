#!/bin/sh

test_description='Check munged command-line options'

. $(dirname "$0")/sharness.sh

test_expect_success 'munged invalid option' '
    test_must_fail "${MUNGED}" --invalid-option
'

for OPT_HELP in '-h' '--help'; do
    test_expect_success "munged ${OPT_HELP}" '
        "${MUNGED}" "${OPT_HELP}" |
        grep -q "^Usage:"
    '
done

for OPT_LICENSE in '-L' '--license'; do
    test_expect_success "munged ${OPT_LICENSE}" '
        "${MUNGED}" "${OPT_LICENSE}" |
        grep -q "GNU General Public License"
    '
done

for OPT_VERSION in '-V' '--version'; do
    test_expect_success "munged ${OPT_VERSION}" '
        "${MUNGED}" "${OPT_VERSION}" |
        grep -q "^munge-[0-9.]*"
    '
done

test_expect_failure 'finish writing tests' '
    false
'

test_done
