##*****************************************************************************
## $Id: Makefile.am,v 1.2 2003/10/28 22:20:45 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge

LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la

bin_PROGRAMS = \
	munge \
	unmunge

munge_SOURCES = \
	munge.c \
	read.c

unmunge_SOURCES = \
	unmunge.c \
	read.c
