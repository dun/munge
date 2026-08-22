# MUNGE src/libtap/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://github.com/dun/munge>.

include $(top_srcdir)/Make-inc.mk

check_LTLIBRARIES = \
	libtap.la \
	# End of check_LTLIBRARIES

# tap.c calls mmap() with MAP_ANONYMOUS.  "-std=c99" sets __STRICT_ANSI__,
# and glibc before 2.19 then exposes MAP_ANONYMOUS only under _BSD_SOURCE
# or _SVID_SOURCE.
#
# glibc 2.19 added _DEFAULT_SOURCE, which tap.c defines itself.  glibc 2.20
# deprecates _BSD_SOURCE and warns when the macro is defined, and that same
# _DEFAULT_SOURCE suppresses the warning.
#
# A per-target "_CFLAGS" replaces AM_CFLAGS rather than adds to it.
# Omit AM_CFLAGS here.  libtap is vendored source, and the "--enable-debug"
# warning flags would report on code MUNGE does not maintain.  A CFLAGS
# set on the make command line still reaches it.
#
libtap_la_CFLAGS = \
	-D_BSD_SOURCE \
	# End of libtap_la_CFLAGS

libtap_la_SOURCES = \
	tap.c \
	tap.h \
	# End of libtap_la_SOURCES
