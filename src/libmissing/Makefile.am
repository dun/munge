##*****************************************************************************
## $Id: Makefile.am,v 1.3 2004/04/08 22:09:45 dun Exp $
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

noinst_LTLIBRARIES = \
	libmissing.la

libmissing_la_LIBADD = \
	@LTLIBOBJS@

libmissing_la_SOURCES = \
	getopt.h \
	getopt.c \
	getopt1.c \
	missing.h
