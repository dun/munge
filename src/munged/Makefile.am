# MUNGE src/munged/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munged.8.in \
	# End of TEMPLATE_FILES

SUBSTITUTE_FILES = \
	munged.8 \
	# End of SUBSTITUTE_FILES

EXTRA_DIST = \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < '$(srcdir)/$@.in' > '$(builddir)/$@'

munged.8: munged.8.in

sbin_PROGRAMS = \
	munged \
	# End of sbin_PROGRAMS

munged_CFLAGS = \
	$(AM_CFLAGS) \
	$(CRYPTO_CFLAGS) \
	# End of munged_CFLAGS

munged_CPPFLAGS = \
	-DLOCALSTATEDIR='"$(localstatedir)"' \
	-DRUNSTATEDIR='"$(runstatedir)"' \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-DWITH_PTHREADS \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge \
	# End of munged_CPPFLAGS

munged_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBPTHREAD) \
	$(LIBBZ2) \
	$(LIBRT) \
	$(LIBZ) \
	$(CRYPTO_LIBS) \
	# End of munged_LDADD

munged_SOURCES = \
	munged.c \
	auth_recv.c \
	auth_recv.h \
	base64.c \
	base64.h \
	cipher.c \
	cipher.h \
	clock.c \
	clock.h \
	conf.c \
	conf.h \
	cred.c \
	cred.h \
	dec.c \
	dec.h \
	enc.c \
	enc.h \
	gids.c \
	gids.h \
	hash.c \
	hash.h \
	job.c \
	job.h \
	lock.c \
	lock.h \
	net.c \
	net.h \
	path.c \
	path.h \
	random.c \
	random.h \
	replay.c \
	replay.h \
	thread.c \
	thread.h \
	timer.c \
	timer.h \
	work.c \
	work.h \
	zip.c \
	zip.h \
	$(top_srcdir)/src/common/crypto.c \
	$(top_srcdir)/src/common/crypto.h \
	$(top_srcdir)/src/common/entropy.c \
	$(top_srcdir)/src/common/entropy.h \
	$(top_srcdir)/src/common/mac.c \
	$(top_srcdir)/src/common/mac.h \
	$(top_srcdir)/src/common/md.c \
	$(top_srcdir)/src/common/md.h \
	$(top_srcdir)/src/common/query.c \
	$(top_srcdir)/src/common/query.h \
	$(top_srcdir)/src/common/rotate.c \
	$(top_srcdir)/src/common/rotate.h \
	$(top_srcdir)/src/common/xgetgr.c \
	$(top_srcdir)/src/common/xgetgr.h \
	$(top_srcdir)/src/common/xgetpw.c \
	$(top_srcdir)/src/common/xgetpw.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h \
	# End of munged_SOURCES

# For dependencies on LOCALSTATEDIR, RUNSTATEDIR, and SYSCONFDIR via the
#   #defines for MUNGE_AUTH_SERVER_DIR, MUNGE_KEYFILE_PATH, MUNGE_LOGFILE_PATH,
#   MUNGE_PIDFILE_PATH, MUNGE_SEEDFILE_PATH, and MUNGE_SOCKET_NAME.
#
$(srcdir)/munged-conf.$(OBJEXT): Makefile

man_MANS = \
	munged.8 \
	# End of man_MANS

check_PROGRAMS = \
	$(TESTS) \
	# End of check_PROGRAMS

TESTS = \
	base64_test \
	# End of TESTS

base64_test_CPPFLAGS = \
	-I$(top_srcdir)/src/libtap \
	# End of base64_test_CPPFLAGS

base64_test_LDADD = \
	$(top_builddir)/src/libtap/libtap.la \
	# End of base64_test_LDADD

base64_test_SOURCES = \
	base64.c \
	base64.h \
	base64_test.c \
	# End of base64_test_SOURCES
