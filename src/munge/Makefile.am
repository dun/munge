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

bin_PROGRAMS = \
	munge \
	unmunge \
	remunge

munge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la

munge_SOURCES = \
	munge.c \
	read.c

unmunge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la

unmunge_SOURCES = \
	unmunge.c \
	read.c

remunge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBPTHREAD)

remunge_SOURCES = \
	remunge.c

man_MANS = \
	munge.1 \
	unmunge.1 \
	remunge.1

install-data-local:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(bindir)
	$(INSTALL) -d -m 0755 $(DESTDIR)$(mandir)
	$(INSTALL) -d -m 0755 $(DESTDIR)$(mandir)/man1
