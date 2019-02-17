# MUNGE src/libmissing/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

noinst_LTLIBRARIES = \
	libmissing.la \
	# End of noinst_LTLIBRARIES

libmissing_la_LIBADD = \
	$(LTLIBOBJS) \
	# End of libmissing_la_LIBADD

libmissing_la_SOURCES = \
	getopt.h \
	getopt.c \
	getopt1.c \
	missing.h \
	# End of libmissing_la_SOURCES

EXTRA_libmissing_la_SOURCES = \
	inet_ntop.h \
	strlcat.h \
	strlcpy.h \
	# End of EXTRA_libmissing_la_SOURCES

EXTRA_DIST = \
	URL \
	# End of EXTRA_DIST
