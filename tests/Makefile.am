# MUNGE tests/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://github.com/dun/munge>.

include $(top_srcdir)/Make-inc.mk

TEST_EXTENSIONS = .t

T_LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/build-aux/tap-driver.sh --merge

test_scripts = \
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
	0096-credential-expired.t \
	0097-credential-rewound.t \
	0098-credential-replayed.t \
	0099-credential-decode.t \
	0100-munged-lock.t \
	0101-munged-security-socket.t \
	0102-munged-security-keyfile.t \
	0103-munged-security-logfile.t \
	0104-munged-security-pidfile.t \
	0105-munged-security-seedfile.t \
	0110-munged-origin-addr.t \
	1000-chaos-rpm.t \
	# End of test_scripts

test_programs = \
	ctx_opt_ignore.t \
	# End of test_programs

ctx_opt_ignore_t_CPPFLAGS = \
	-I$(top_srcdir)/src/libmunge \
	-I$(top_srcdir)/src/libtap \
	# End of ctx_opt_ignore_t_CPPFLAGS

ctx_opt_ignore_t_LDADD = \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(top_builddir)/src/libtap/libtap.la \
	# End of ctx_opt_ignore_t_LDADD

ctx_opt_ignore_t_SOURCES = \
	ctx_opt_ignore.c \
	# End of ctx_opt_ignore_t_SOURCES

TESTS = \
	$(test_scripts) \
	$(test_programs) \
	# End of TESTS

EXTRA_DIST = \
	$(test_scripts) \
	0099-credential-decode.cred \
	0099-credential-decode.key \
	0099-credential-decode.out \
	lib-sharness \
	sharness.d \
	sharness.sh \
	valgrind.supp \
	# End of EXTRA_DIST

EXTRA_PROGRAMS = \
	$(test_programs) \
	# End of EXTRA_PROGRAMS

clean-local:
	-rm -f $(test_programs)
	-rm -rf test-results
	-rm -rf trash*directory.*
