#!/bin/sh

test_description='Check to build, install, and test RPMs'

. "$(dirname "$0")/sharness.sh"

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

# Ensure none of the munge RPMs are currently installed in order to prevent
#   overwriting an existing installation.
# It would be quicker to just "rpm --query munge", but that could miss RPMs
#   from a partial (un)install that would interfere with the new installation.
#
if rpm --query --all | grep ^munge-; then
    skip_all='skipping rpm test; munge rpm already installed'
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

# Create a scratch directory for the RPM build.
#
test_expect_success 'setup' '
    MUNGE_RPM_DIR="${TMPDIR:-"/tmp"}/munge-rpm-$$" &&
    mkdir -p "${MUNGE_RPM_DIR}"
'

# Create the dist tarball for rpmbuild and stash it in the scratch directory.
#
test_expect_success 'create dist tarball' '
    cd "${MUNGE_BUILD_DIR}" &&
    rm -f munge-*.tar* &&
    make dist &&
    mv munge-*.tar* "${MUNGE_RPM_DIR}"/ &&
    cd &&
    MUNGE_TARBALL=$(ls "${MUNGE_RPM_DIR}"/munge-*.tar*) &&
    test -f "${MUNGE_TARBALL}" &&
    test_set_prereq MUNGE_TARBALL
'

# Build the source RPM which is needed to install dependencies for building the
#   binary RPMs.
#
test_expect_success MUNGE_TARBALL 'build srpm' '
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
    local BUILDDEP &&
    if command -v dnf >/dev/null 2>&1; then
        BUILDDEP="dnf builddep --assumeyes"
    elif command -v yum-builddep >/dev/null 2>&1; then
        BUILDDEP="yum-builddep"
    else
        echo "builddep command not found"; false
    fi &&
    sudo ${BUILDDEP} "${MUNGE_RPM_DIR}"/SRPMS/*.src.rpm
'

# Build in binary RPMs.
#
test_expect_success MUNGE_TARBALL 'build rpm' '
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
# Save the resulting output for later removing the RPMs that were installed.
#
test_expect_success MUNGE_RPM 'install rpm' '
    sudo rpm --install --verbose "${MUNGE_RPM_DIR}"/RPMS/*/*.rpm \
            >rpm.install.out.$$ &&
    cat rpm.install.out.$$
'

# Create a new key, overwriting an existing key if necessary.
# Run as the munge user since the key dir is 0700 and owned by munge.
# Save the name of the key file for later cleanup.
#
test_expect_success MUNGE_RPM 'create key' '
    sudo --user=munge /usr/sbin/mungekey --force --verbose 2>mungekey.err.$$ &&
    cat mungekey.err.$$ &&
    MUNGE_KEYFILE=$(sed -ne "s/.*\"\([^\"]*\)\".*/\1/p" mungekey.err.$$) &&
    test -n "${MUNGE_KEYFILE}"
'

# Check if the key file has been created.
# Run as the munge user since the key dir is 0700 and owned by munge.
#
test_expect_success MUNGE_RPM 'check key' '
    sudo --user=munge test -f "${MUNGE_KEYFILE}"
'

# Start the munge service.
#
test_expect_success MUNGE_RPM 'start munge service' '
    sudo systemctl start munge.service
'

# Check if the munge service is running.
#
test_expect_success MUNGE_RPM 'check service status' '
    systemctl status --full --no-pager munge.service
'

# Encode a credential, saving the resulting output for multiple decodes.
#
test_expect_success MUNGE_RPM 'encode credential' '
    munge </dev/null >cred.$$
'

# Decode the credential.
#
test_expect_success MUNGE_RPM 'decode credential' '
    unmunge <cred.$$
'

# Decode the same credential again to verify replay detection.
#
test_expect_success MUNGE_RPM 'replay credential' '
    test_must_fail unmunge <cred.$$
'

# Stop the munge service.
#
test_expect_success MUNGE_RPM 'stop munge service' '
    sudo systemctl stop munge.service
'

# Remove the binary RPMs installed earlier in the test.
#
test_expect_success MUNGE_RPM 'remove rpm' '
    grep ^munge- rpm.install.out.$$ >rpm.pkgs.$$ &&
    sudo rpm --erase --verbose $(cat rpm.pkgs.$$)
'

# Verify all of the munge RPMs have been removed since their continued presence
#   would prevent this test from running again.
#
test_expect_success MUNGE_RPM 'verify rpm removal' '
    rpm --query --all >rpm.query.out.$$ &&
    ! grep ^munge- rpm.query.out.$$
'

# Remove the key dir after checking to make sure the derived pathname ends with
#   "/munge".
#
test_expect_success MUNGE_RPM 'remove key' '
    local MUNGE_KEYFILEDIR=$(dirname "${MUNGE_KEYFILE}") &&
    expr "${MUNGE_KEYFILEDIR}" : "/.*/munge$" >/dev/null 2>&1 &&
    echo "${MUNGE_KEYFILEDIR}" &&
    sudo rm -rf "${MUNGE_KEYFILEDIR}" &&
    test_set_prereq SUCCESS
'

# Remove the scratch directory if all tests succeeded unless MUNGE_NOCLEAN
#   is set.
#
test_expect_success SUCCESS 'cleanup' '
    if test "x${MUNGE_NOCLEAN}" = xt; then
        echo "rpm dir is \"${MUNGE_RPM_DIR}\""
    else
        rm -rf "${MUNGE_RPM_DIR}"
    fi
'

test_done
