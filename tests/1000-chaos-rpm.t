#!/bin/sh

test_description='Check to build, install, and test RPMs'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Check for the guard variable.
# Warning: This test performs system modifications: installs/removes RPMs,
#   creates/removes users, and manages services.  Set MUNGE_CHAOS=t to enable.
#
if test "x${MUNGE_CHAOS}" != xt; then
    skip_all="skipping tests: chaos not enabled"
    test_done
fi

# Ensure EXPENSIVE tests are allowed.
#
if ! test_have_prereq EXPENSIVE; then
    skip_all="skipping tests: --long-tests not specified"
    test_done
fi

# Ensure this is a RHEL-based system (AlmaLinux, CentOS, Fedora).
#
if ! grep -E -q '^ID.*=.*\b(rhel|fedora)\b' /etc/os-release 2>/dev/null; then
    local id &&
    id=$(sed -ne '/^ID=/!d; s/.*=//; s/"//g; p; q' /etc/os-release 2>/dev/null)
    skip_all="skipping tests: ${id:+${id} }system type not supported"
    test_done
fi

# Ensure the rpmbuild executable is already installed.
#
if ! command -v rpmbuild >/dev/null 2>&1; then
    skip_all="skipping tests: rpmbuild not installed"
    test_done
fi

# Ensure that non-interactive sudo is available.
#
if ! test_have_prereq SUDO; then
    skip_all="skipping tests: sudo not enabled"
    test_done
fi

# Remove the scratch directory created by "setup" unless [debug] is set.
# If called from a signal trap, always remove the directory.
#
rpm_dir_cleanup()
{
    local called_from_trap="${1:-}"
    if test "x${debug}" != xt || test "x${called_from_trap}" = xt; then
        rm -rf "${MUNGE_RPM_DIR}"
    fi
}

# Create a scratch directory for the RPM build.
# Provide [MUNGE_RPM_DIR] for later tests.
#
test_expect_success 'setup' '
    MUNGE_RPM_DIR="${TMPDIR:-"/tmp"}/munge-rpm-$$" &&
    mkdir -p "${MUNGE_RPM_DIR}" &&
    trap "rpm_dir_cleanup t; EXIT_OK=t; exit 130" INT &&
    trap "rpm_dir_cleanup t; EXIT_OK=t; exit 143" TERM &&
    cleanup rpm_dir_cleanup
'

# Create the dist tarball for rpmbuild and stash it in the scratch directory.
# Provide [MUNGE_TARBALL] for later tests.
#
test_expect_success 'create dist tarball' '
    cd "${MUNGE_BUILD_DIR}" &&
    rm -f munge-*.tar* &&
    make dist &&
    mv munge-*.tar* "${MUNGE_RPM_DIR}"/ &&
    cd &&
    MUNGE_TARBALL=$(ls "${MUNGE_RPM_DIR}"/munge-*.tar*) &&
    test -f "${MUNGE_TARBALL}" &&
    test_set_prereq MUNGE_DIST
'

# Build the source RPM to enable dependency installation via builddep.
# Use --with=check so conditional BuildRequires for testing are included.
# Use --without=verify since signature verification requires manual key entry.
#
test_expect_success MUNGE_DIST 'build srpm' '
    rpmbuild -ts --with=check --without=verify \
            --define="source_date_epoch_from_changelog 0" \
            --define="_builddir %{_topdir}/BUILD" \
            --define="_buildrootdir %{_topdir}/BUILDROOT" \
            --define="_rpmdir %{_topdir}/RPMS" \
            --define="_sourcedir %{_topdir}/SOURCES" \
            --define="_specdir %{_topdir}/SPECS" \
            --define="_srcrpmdir %{_topdir}/SRPMS" \
            --define="_topdir ${MUNGE_RPM_DIR}" \
            "${MUNGE_TARBALL}" &&
    test_set_prereq MUNGE_SRPM
'

# Install build dependencies needed for building the binary RPMs.
#
test_expect_success MUNGE_SRPM 'install builddeps' '
    local builddep &&
    if command -v dnf >/dev/null 2>&1; then
        builddep="dnf builddep --assumeyes"
    elif command -v yum-builddep >/dev/null 2>&1; then
        builddep="yum-builddep"
    else
        echo "builddep command not found"; false
    fi &&
    sudo ${builddep} "${MUNGE_RPM_DIR}"/SRPMS/*.src.rpm
'

# Build binary RPMs.
# Use --without=check to skip the test suite.  The nested make check fails
#   under automake's test harness (unable to create .trs/.log files).
#
test_expect_success MUNGE_DIST 'build rpm' '
    rpmbuild -tb --without=check --without=verify \
            --define="source_date_epoch_from_changelog 0" \
            --define="_builddir %{_topdir}/BUILD" \
            --define="_buildrootdir %{_topdir}/BUILDROOT" \
            --define="_rpmdir %{_topdir}/RPMS" \
            --define="_sourcedir %{_topdir}/SOURCES" \
            --define="_specdir %{_topdir}/SPECS" \
            --define="_srcrpmdir %{_topdir}/SRPMS" \
            --define="_topdir ${MUNGE_RPM_DIR}" \
            --pipe="sed \"s/^\(\(not \)\?ok\)\b/ \1/\"" \
            "${MUNGE_TARBALL}" &&
    test_set_prereq MUNGE_RPM
'

# Remove any existing munge RPMs to ensure a clean installation test.
#
test_expect_success MUNGE_RPM 'remove existing rpms' '
    local pkgs &&
    if pkgs=$(rpm --query --all |
            grep -E "^munge-([0-9]|debug|devel|libs)"); then
        sudo rpm --erase --verbose ${pkgs}
    fi
'

# Install the binary RPMs.
# Save the resulting output for later removal of the RPMs that were installed.
#
test_expect_success MUNGE_RPM 'install rpm' '
    sudo rpm --install --verbose "${MUNGE_RPM_DIR}"/RPMS/*/*.rpm \
            >rpm.install.$$ &&
    cat rpm.install.$$ &&
    test_set_prereq MUNGE_INSTALL
'

# Create a new key, overwriting an existing key if necessary.
# Run as the munge user since the keyfile dir is 0700 and owned by munge.
# Provide [MUNGE_KEYFILE] for later tests.
#
test_expect_success MUNGE_INSTALL 'create key' '
    sudo --user=munge /usr/sbin/mungekey --force --verbose 2>mungekey.err.$$ &&
    cat mungekey.err.$$ &&
    MUNGE_KEYFILE=$(sed -ne "s/.*\"\([^\"]*\)\".*/\1/p" mungekey.err.$$) &&
    test -n "${MUNGE_KEYFILE}"
'

# Check if the keyfile has been created.
# Run as the munge user since the keyfile dir is 0700 and owned by munge.
#
test_expect_success MUNGE_INSTALL 'check key' '
    sudo --user=munge test -f "${MUNGE_KEYFILE}"
'

# Start the munge service.
#
test_expect_success MUNGE_INSTALL 'start munge service' '
    sudo systemctl start munge.service
'

# Check if the munge service is running.
#
test_expect_success MUNGE_INSTALL 'check service status' '
    systemctl status --full --no-pager munge.service
'

# Encode a credential, saving the resulting output for multiple decodes.
#
test_expect_success MUNGE_INSTALL 'encode credential' '
    munge </dev/null >cred.$$
'

# Decode the credential.
#
test_expect_success MUNGE_INSTALL 'decode credential' '
    unmunge <cred.$$
'

# Decode the same credential again to verify replay detection.
#
test_expect_success MUNGE_INSTALL 'replay credential' '
    test_must_fail unmunge <cred.$$
'

# Stop the munge service.
#
test_expect_success MUNGE_INSTALL 'stop munge service' '
    sudo systemctl stop munge.service
'

# Remove the munge RPMs installed previously.
#
test_expect_success MUNGE_INSTALL 'remove rpm' '
    grep -E "^munge-([0-9]|debug|devel|libs)" rpm.install.$$ >rpm.pkgs.$$ &&
    sudo rpm --erase --verbose $(cat rpm.pkgs.$$)
'

# Verify all of the munge RPMs have been removed since their continued presence
#   would prevent this test from running again.
#
test_expect_success MUNGE_INSTALL 'verify rpm removal' '
    rpm --query --all >rpm.query.$$ &&
    ! grep -E "^munge-([0-9]|debug|devel|libs)" rpm.query.$$
'

# Verify the ldconfig cache has been updated to remove libmunge entries.
# The %postun scriptlet should call ldconfig after package removal.
#
test_expect_success MUNGE_INSTALL 'verify libmunge not in ldconfig' '
    ldconfig -p >ldconfig.out.$$ &&
    ! grep libmunge ldconfig.out.$$
'

# Remove the keyfile directory after verifying the path ends with "/munge".
#
test_expect_success MUNGE_INSTALL 'remove key' '
    local keyfiledir &&
    keyfiledir=$(dirname "${MUNGE_KEYFILE}") &&
    expr "${keyfiledir}" : "/.*/munge$" >/dev/null 2>&1 &&
    echo "${keyfiledir}" &&
    sudo rm -rf "${keyfiledir}"
'

# Remove the munge user and group created in the RPM specfile to ensure they
#   will be recreated when the binary RPMs are installed.
#
test_expect_success MUNGE_INSTALL 'remove munge user' '
    sudo userdel munge
'

test_done
