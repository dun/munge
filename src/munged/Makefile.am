##*****************************************************************************
## $Id: Makefile.am,v 1.5 2003/11/26 23:07:49 dun Exp $
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
	-lpthread \
	-lcrypto

munged_SOURCES = \
	auth.c \
	auth.h \
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
	dec_v1.c \
	dec_v1.h \
	enc_v1.c \
	enc_v1.h \
	hash.c \
	hash.h \
	lookup.c \
	lookup.h \
	mac.c \
	mac.h \
	md.c \
	md.h \
	msg_server.c \
	msg_server.h \
	random.c \
	random.h \
	replay.c \
	replay.h \
	sock.c \
	sock.h \
	thread.c \
	thread.h \
	timer.c \
	timer.h \
	munged.c

check_PROGRAMS = $(TESTS)

TESTS = \
	base64_test

base64_test_SOURCES = \
	base64.c \
	base64.h \
	base64_test.c
