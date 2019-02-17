# MUNGE src/munge/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.1.in \
	remunge.1.in \
	unmunge.1.in \
	# End of TEMPLATE_FILES

SUBSTITUTE_FILES = \
	munge.1 \
	remunge.1 \
	unmunge.1 \
	# End of SUBSTITUTE_FILES

EXTRA_DIST = \
	$(TEMPLATE_FILES) \
	# End of EXTRA_DIST

CLEANFILES = \
	$(SUBSTITUTE_FILES) \
	# End of CLEANFILES

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munge.1: munge.1.in
remunge.1: remunge.1.in
unmunge.1: unmunge.1.in

bin_PROGRAMS = \
	munge \
	remunge \
	unmunge \
	# End of bin_PROGRAMS

munge_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge \
	# End of munge_CPPFLAGS

munge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	# End of munge_LDADD

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
	$(top_srcdir)/src/common/xsignal.h \
	# End of munge_SOURCES

remunge_CPPFLAGS = \
	-DWITH_PTHREADS \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge \
	# End of remunge_CPPFLAGS

remunge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(LIBPTHREAD) \
	# End of remunge_LDADD

remunge_SOURCES = \
	remunge.c \
	$(top_srcdir)/src/common/query.c \
	$(top_srcdir)/src/common/query.h \
	$(top_srcdir)/src/common/xgetgr.c \
	$(top_srcdir)/src/common/xgetgr.h \
	$(top_srcdir)/src/common/xgetpw.c \
	$(top_srcdir)/src/common/xgetpw.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h \
	# End of remunge_SOURCES

unmunge_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge \
	# End of unmunge_CPPFLAGS

unmunge_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	# End of unmunge_LDADD

unmunge_SOURCES = \
	unmunge.c \
	read.c \
	read.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h \
	# End of unmunge_SOURCES

man_MANS = \
	munge.1 \
	remunge.1 \
	unmunge.1 \
	# End of man_MANS
