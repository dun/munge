##*****************************************************************************
## $Id: Makefile.am,v 1.10 2004/05/01 05:08:26 dun Exp $
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
	auth_send.c \
	auth_send.h \
	ctx.c \
	ctx.h \
	decode.c \
	encode.c \
	msg_client.c \
	msg_client.h \
	strerror.c \
	strings.c \
	munge.h
