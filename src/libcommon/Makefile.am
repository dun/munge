##*****************************************************************************
## $Id: Makefile.am,v 1.3 2003/05/03 00:41:00 dun Exp $
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
