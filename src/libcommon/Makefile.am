##*****************************************************************************
## $Id: Makefile.am,v 1.2 2003/04/08 18:16:16 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

CPPFLAGS = \
	-I$(top_srcdir)/src/libmunge

noinst_LTLIBRARIES = \
	libcommon.la

libcommon_la_SOURCES = \
	common.h \
	dprintf.c \
	dprintf.h \
	fd.c \
	fd.h \
	license.c \
	license.h \
	log.c \
	log.h \
	munge_defs.h \
	munge_msg.c \
	munge_msg.h \
	posignal.c \
	posignal.h \
	str.c \
	str.h
