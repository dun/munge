##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge

sbin_PROGRAMS = \
	munged

munged_CFLAGS = \
	-DWITH_PTHREADS

munged_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBPTHREAD) \
	-lcrypto \
	$(LIBBZ2) \
	$(LIBZ)

munged_SOURCES = \
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
	crypto_log.c \
	crypto_log.h \
	crypto_thread.c \
	crypto_thread.h \
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
	lookup.c \
	lookup.h \
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
	munged.c

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
