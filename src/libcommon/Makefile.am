##*****************************************************************************
## $Id: Makefile.am,v 1.5 2004/05/01 05:08:26 dun Exp $
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
	munge_defs.h \
	munge_msg.c \
	munge_msg.h \
	posignal.c \
	posignal.h \
	str.c \
	str.h
