##*****************************************************************************
## $Id: Makefile.am,v 1.9 2004/04/09 04:52:13 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

include_HEADERS = \
	munge.h

lib_LTLIBRARIES = \
	libmunge.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing

libmunge_la_LIBADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(LIBSOCKET)

libmunge_la_SOURCES = \
	ctx.c \
	ctx.h \
	decode.c \
	encode.c \
	msg_client.c \
	msg_client.h \
	strerror.c \
	strings.c \
	munge.h
