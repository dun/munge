##*****************************************************************************
## $Id: Makefile.am,v 1.7 2004/11/24 00:21:57 dun Exp $
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
	auth_policy.h \
	fd.c \
	fd.h \
	license.c \
	license.h \
	log.c \
	log.h \
	msg.c \
	msg.h \
	munge_defs.h \
	posignal.c \
	posignal.h \
	str.c \
	str.h

man_MANS = \
	munge.7
