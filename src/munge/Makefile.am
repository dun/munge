# MUNGE src/munge/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.1.in \
	remunge.1.in \
	unmunge.1.in

SUBSTITUTE_FILES = \
	munge.1 \
	remunge.1 \
	unmunge.1

EXTRA_DIST = \
	$(TEMPLATE_FILES)

CLEANFILES = \
	$(SUBSTITUTE_FILES)

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munge.1: munge.1.in
remunge.1: remunge.1.in
unmunge.1: unmunge.1.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge

bin_PROGRAMS = \
	munge \
	remunge \
	unmunge

munge_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	$(AM_CPPFLAGS)

munge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la

munge_SOURCES = \
	munge.c \
	read.c \
	read.h \
	$(top_srcdir)/src/common/query.c \
	$(top_srcdir)/src/common/query.h \
	$(top_srcdir)/src/common/xgetgr.c \
	$(top_srcdir)/src/common/xgetgr.h \
	$(top_srcdir)/src/common/xgetpw.c \
	$(top_srcdir)/src/common/xgetpw.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h

remunge_CPPFLAGS = \
	-DWITH_PTHREADS \
	-I$(top_srcdir)/src/common \
	$(AM_CPPFLAGS)

remunge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBPTHREAD)

remunge_SOURCES = \
	remunge.c \
	$(top_srcdir)/src/common/query.c \
	$(top_srcdir)/src/common/query.h \
	$(top_srcdir)/src/common/xgetgr.c \
	$(top_srcdir)/src/common/xgetgr.h \
	$(top_srcdir)/src/common/xgetpw.c \
	$(top_srcdir)/src/common/xgetpw.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h

unmunge_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	$(AM_CPPFLAGS)

unmunge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la

unmunge_SOURCES = \
	unmunge.c \
	read.c \
	read.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h

man_MANS = \
	munge.1 \
	remunge.1 \
	unmunge.1
