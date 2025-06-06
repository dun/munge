# MUNGE src/common/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://github.com/dun/munge>.

include $(top_srcdir)/Make-inc.mk

TEST_EXTENSIONS = .test

TEST_LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/build-aux/tap-driver.sh --merge

AM_TESTSUITE_SUMMARY_HEADER = ' of src/common/ for $(PACKAGE_STRING)'

TESTS = \
	hkdf_api.test \
	hkdf_rfc.test \
	mac.test \
	# End of TESTS

check_PROGRAMS = \
	$(TESTS) \
	# End of check_PROGRAMS

hkdf_api_test_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmunge \
	-I$(top_srcdir)/src/libtap \
	$(CRYPTO_CFLAGS) \
	# End of hkdf_api_test_CPPFLAGS

hkdf_api_test_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(CRYPTO_LIBS) \
	# End of hkdf_api_test_LDADD

hkdf_api_test_SOURCES = \
	crypto.c \
	crypto.h \
	hkdf.c \
	hkdf.h \
	mac.c \
	mac.h \
	md.c \
	md.h \
	hkdf_api_test.c \
	# End of hkdf_api_test_SOURCES

hkdf_rfc_test_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmunge \
	-I$(top_srcdir)/src/libtap \
	$(CRYPTO_CFLAGS) \
	# End of hkdf_rfc_test_CPPFLAGS

hkdf_rfc_test_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(CRYPTO_LIBS) \
	# End of hkdf_rfc_test_LDADD

hkdf_rfc_test_SOURCES = \
	crypto.c \
	crypto.h \
	hkdf.c \
	hkdf.h \
	mac.c \
	mac.h \
	md.c \
	md.h \
	hkdf_rfc_test.c \
	# End of hkdf_rfc_test_SOURCES

mac_test_CPPFLAGS = \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmunge \
	-I$(top_srcdir)/src/libtap \
	$(CRYPTO_CFLAGS) \
	# End of mac_test_CPPFLAGS

mac_test_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(CRYPTO_LIBS) \
	# End of mac_test_LDADD

mac_test_SOURCES = \
	crypto.c \
	crypto.h \
	mac.c \
	mac.h \
	md.c \
	md.h \
	mac_test.c \
	# End of mac_test_SOURCES

.NOTPARALLEL: hkdf_api_test hkdf_rfc_test mac_test
