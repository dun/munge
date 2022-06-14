# MUNGE t/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEST_EXTENSIONS = .t

T_LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

TESTS = \
	0001-env-vars.t \
	0002-smiple.t \
	0010-basic.t \
	0011-munged-cmdline.t \
	0012-munge-cmdline.t \
	0013-unmunge-cmdline.t \
	0015-mungekey-cmdline.t \
	0021-munged-valgrind.t \
	0022-munge-valgrind.t \
	0023-unmunge-valgrind.t \
	0025-mungekey-valgrind.t \
	0099-credential-decode.t \
	0100-munged-lock.t \
	0101-munged-security-socket.t \
	0102-munged-security-keyfile.t \
	0103-munged-security-logfile.t \
	0104-munged-security-pidfile.t \
	0105-munged-security-seedfile.t \
	0110-munged-origin-addr.t \
	# End of TESTS

EXTRA_DIST = \
	$(TESTS) \
	0000-sharness.t \
	0099-credential-decode.cred \
	0099-credential-decode.key \
	0099-credential-decode.out \
	sharness.d \
	sharness.sh \
	test-terminal.perl \
	valgrind.supp \
	# End of EXTRA_DIST

clean-local:
	-rm -rf test-results
	-rm -rf trash-directory.*
