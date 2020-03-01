# MUNGE src/common/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

check_PROGRAMS = \
	$(TESTS) \
	# End of check_PROGRAMS

TESTS = \
	hkdf_test \
	path_canonicalize_test \
	# End of TESTS

hkdf_test_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmunge \
	-I$(top_srcdir)/src/libtap \
	$(CRYPTO_CFLAGS) \
	# End of hkdf_test_CPPFLAGS

hkdf_test_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(CRYPTO_LIBS) \
	# End of hkdf_test_LDADD

hkdf_test_SOURCES = \
	crypto.c \
	crypto.h \
	hkdf.c \
	hkdf.h \
	mac.c \
	mac.h \
	md.c \
	md.h \
	hkdf_test.c \
	# End of hkdf_test_SOURCES

path_canonicalize_test_CPPFLAGS = \
	-I$(top_srcdir)/src/libtap \
	# End of path_canonicalize_test_CPPFLAGS

path_canonicalize_test_LDADD = \
	$(top_builddir)/src/libtap/libtap.la \
	# End of path_canonicalize_test_LDADD

path_canonicalize_test_SOURCES = \
	path.c \
	path.h \
	path_canonicalize_test.c \
	# End of path_canonicalize_test_SOURCES

.NOTPARALLEL: hkdf_test
