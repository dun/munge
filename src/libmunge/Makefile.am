##*****************************************************************************
## $Id: Makefile.am,v 1.4 2003/04/08 18:16:16 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

include_HEADERS = \
	munge.h

lib_LTLIBRARIES = \
	libmunge.la

CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing

libmunge_la_LIBADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la

libmunge_la_SOURCES = \
	code.c \
	ctx.c \
	ctx.h \
	msg_client.c \
	msg_client.h \
	munge.h
