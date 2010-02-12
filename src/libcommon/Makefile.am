##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libmunge

noinst_LTLIBRARIES = \
	libcommon.la

libcommon_la_SOURCES = \
	common.h \
	fd.c \
	fd.h \
	license.c \
	license.h \
	log.c \
	log.h \
	m_msg.c \
	m_msg.h \
	munge_defs.h \
	posignal.c \
	posignal.h \
	str.c \
	str.h \
	version.c \
	version.h

man_MANS = \
	munge.7

install-data-local:
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(mandir)/man7"
	chmod 755 "$(DESTDIR)$(mandir)"
