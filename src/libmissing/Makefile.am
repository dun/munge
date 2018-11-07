# MUNGE src/libmissing/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

noinst_LTLIBRARIES = \
	libmissing.la

libmissing_la_LIBADD = \
	$(LTLIBOBJS)

libmissing_la_SOURCES = \
	getopt.h \
	getopt.c \
	getopt1.c \
	missing.h

EXTRA_libmissing_la_SOURCES = \
	inet_ntop.h \
	strlcat.h \
	strlcpy.h

EXTRA_DIST = \
	URL
