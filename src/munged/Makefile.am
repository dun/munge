# MUNGE src/munged/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge

sbin_PROGRAMS = \
	munged

munged_CFLAGS = \
	$(AM_CFLAGS) \
	$(CRYPTO_CFLAGS)

munged_CPPFLAGS = \
	-DWITH_PTHREADS \
	-I$(top_srcdir)/src/common \
	$(AM_CPPFLAGS)

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
	$(top_srcdir)/src/common/query.c \
	$(top_srcdir)/src/common/query.h \
	$(top_srcdir)/src/common/xgetgr.c \
	$(top_srcdir)/src/common/xgetgr.h \
	$(top_srcdir)/src/common/xgetpw.c \
	$(top_srcdir)/src/common/xgetpw.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h

man_MANS = \
	munged.8

check_PROGRAMS = $(TESTS)

TESTS = \
	base64_test

base64_test_SOURCES = \
	base64.c \
	base64.h \
	base64_test.c

install-data-local:
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(sbindir)"
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(mandir)/man8"
	chmod 755 "$(DESTDIR)$(sbindir)"
	chmod 755 "$(DESTDIR)$(mandir)"
