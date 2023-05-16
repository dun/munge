#!/bin/sh

test_description='Check to build, install, and test RPMs'

: "${SHARNESS_TEST_OUTDIR:=$(pwd)}"
: "${SHARNESS_TEST_SRCDIR:=$(cd "$(dirname "$0")" && pwd)}"
. "${SHARNESS_TEST_SRCDIR}/sharness.sh"

# Check for the guard variable.
#
if test "x${MUNGE_CHAOS}" != xt; then
    skip_all='skipping rpm test; chaos not enabled'
    test_done
fi

# Ensure this is a RedHat-based system.
# This regexp matches recent AlmaLinux, CentOS, and Fedora.
#
if grep -E '^ID.*=.*\b(rhel|fedora)\b' /etc/os-release >/dev/null 2>&1; then :
else
    skip_all='skipping rpm test; not a supported redhat-based system'
    test_done
fi

# Ensure the rpmbuild executable is already installed.
#
if command -v rpmbuild >/dev/null 2>&1; then :; else
    skip_all='skipping rpm test; rpmbuild not installed'
    test_done
fi

# Ensure that non-interactive sudo is available.
#
if test_have_prereq SUDO; then :; else
    skip_all='skipping rpm test; sudo not enabled'
    test_done
fi

# Ensure none of the munge RPMs are currently installed in order to prevent
#   overwriting an existing installation.
# It would be quicker to just "rpm --query munge", but that could miss RPMs
#   from a partial (un)install that would interfere with the new installation.
#
if rpm --query --all | grep ^munge-; then
    skip_all='skipping rpm test; munge rpm already installed'
    test_done
fi

# Create a scratch directory for the RPM build.
# Provide [MUNGE_RPM_DIR] for later checks.
#
test_expect_success 'setup' '
    MUNGE_RPM_DIR="${TMPDIR:-"/tmp"}/munge-rpm-$$" &&
    mkdir -p "${MUNGE_RPM_DIR}"
'

# Create the dist tarball for rpmbuild and stash it in the scratch directory.
# Provide [MUNGE_TARBALL] for later checks.
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

# Build the source RPM which is needed to install dependencies for building the
#   binary RPMs.
#
test_expect_success MUNGE_DIST 'build srpm' '
    rpmbuild -ts --without=check --without=verify \
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

# Build in binary RPMs.
#
test_expect_success MUNGE_DIST 'build rpm' '
    rpmbuild -tb --without=check --without=verify \
            --define="_builddir %{_topdir}/BUILD" \
            --define="_buildrootdir %{_topdir}/BUILDROOT" \
            --define="_rpmdir %{_topdir}/RPMS" \
            --define="_sourcedir %{_topdir}/SOURCES" \
            --define="_specdir %{_topdir}/SPECS" \
            --define="_srcrpmdir %{_topdir}/SRPMS" \
            --define="_topdir ${MUNGE_RPM_DIR}" \
            "${MUNGE_TARBALL}" &&
    test_set_prereq MUNGE_RPM
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
# Provide [MUNGE_KEYFILE] for later cleanup.
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

# Remove the binary RPMs installed previously.
#
test_expect_success MUNGE_INSTALL 'remove rpm' '
    grep ^munge- rpm.install.$$ >rpm.pkgs.$$ &&
    sudo rpm --erase --verbose $(cat rpm.pkgs.$$)
'

# Verify all of the munge RPMs have been removed since their continued presence
#   would prevent this test from running again.
#
test_expect_success MUNGE_INSTALL 'verify rpm removal' '
    rpm --query --all >rpm.query.$$ &&
    ! grep ^munge- rpm.query.$$
'

# Remove the keyfile dir after checking to make sure the derived pathname ends
#   with "/munge".
#
test_expect_success MUNGE_INSTALL 'remove key' '
    local keyfiledir=$(dirname "${MUNGE_KEYFILE}") &&
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

# Remove the scratch directory unless [debug] is set.
#
test_expect_success 'cleanup' '
    if test "x${debug}" = xt; then
        echo "rpm dir is \"${MUNGE_RPM_DIR}\""
    else
        rm -rf "${MUNGE_RPM_DIR}"
    fi
'

test_done
