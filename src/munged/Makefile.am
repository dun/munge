# MUNGE src/munged/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munged.8.in

SUBSTITUTE_FILES = \
	munged.8

EXTRA_DIST = \
	$(TEMPLATE_FILES)

CLEANFILES = \
	$(SUBSTITUTE_FILES)

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munged.8: munged.8.in

sbin_PROGRAMS = \
	munged

munged_CFLAGS = \
	$(AM_CFLAGS) \
	$(CRYPTO_CFLAGS)

munged_CPPFLAGS = \
	-DLOCALSTATEDIR='"$(localstatedir)"' \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-DWITH_PTHREADS \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge

munged_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBPTHREAD) \
	$(LIBBZ2) \
	$(LIBZ) \
	$(CRYPTO_LIBS)

munged_SOURCES = \
	munged.c \
	auth_recv.c \
	auth_recv.h \
	base64.c \
	base64.h \
	cipher.c \
	cipher.h \
	conf.c \
	conf.h \
	cred.c \
	cred.h \
	crypto.c \
	crypto.h \
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
	mac.c \
	mac.h \
	md.c \
	md.h \
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
	$(top_srcdir)/src/common/entropy.c \
	$(top_srcdir)/src/common/entropy.h \
	$(top_srcdir)/src/common/query.c \
	$(top_srcdir)/src/common/query.h \
	$(top_srcdir)/src/common/xgetgr.c \
	$(top_srcdir)/src/common/xgetgr.h \
	$(top_srcdir)/src/common/xgetpw.c \
	$(top_srcdir)/src/common/xgetpw.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h

# For dependencies on LOCALSTATEDIR and SYSCONFDIR via the #defines for
#   MUNGE_KEYFILE_PATH, MUNGED_LOGFILE, MUNGED_PIDFILE, MUNGED_RANDOM_SEED,
#   MUNGE_AUTH_SERVER_DIR, and MUNGE_SOCKET_NAME.
#
$(srcdir)/munged-conf.$(OBJEXT): Makefile

man_MANS = \
	munged.8

check_PROGRAMS = $(TESTS)

TESTS = \
	base64_test

base64_test_SOURCES = \
	base64.c \
	base64.h \
	base64_test.c
