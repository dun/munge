##*****************************************************************************
## $Id: Makefile.am,v 1.3 2004/04/09 04:52:13 dun Exp $
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
	unmunge

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
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBNSL)

unmunge_SOURCES = \
	unmunge.c \
	read.c
