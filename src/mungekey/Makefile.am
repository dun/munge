# MUNGE src/mungekey/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	mungekey.8.in

SUBSTITUTE_FILES = \
	mungekey.8

EXTRA_DIST = \
	$(TEMPLATE_FILES)

CLEANFILES = \
	$(SUBSTITUTE_FILES)

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

mungekey.8: mungekey.8.in

sbin_PROGRAMS = \
	mungekey

mungekey_CFLAGS = \
	$(AM_CFLAGS) \
	$(CRYPTO_CFLAGS)

mungekey_CPPFLAGS = \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libcommon \
	-I$(top_srcdir)/src/libmissing \
	-I$(top_srcdir)/src/libmunge

mungekey_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.la \
	$(top_builddir)/src/libmissing/libmissing.la \
	$(top_builddir)/src/libmunge/libmunge.la \
	$(CRYPTO_LIBS)

mungekey_SOURCES = \
	mungekey.c \
	conf.c \
	conf.h \
	key.c \
	key.h \
	$(top_srcdir)/src/common/crypto.c \
	$(top_srcdir)/src/common/crypto.h \
	$(top_srcdir)/src/common/entropy.c \
	$(top_srcdir)/src/common/entropy.h \
	$(top_srcdir)/src/common/hkdf.c \
	$(top_srcdir)/src/common/hkdf.h \
	$(top_srcdir)/src/common/mac.c \
	$(top_srcdir)/src/common/mac.h \
	$(top_srcdir)/src/common/md.c \
	$(top_srcdir)/src/common/md.h \
	$(top_srcdir)/src/common/rotate.c \
	$(top_srcdir)/src/common/rotate.h \
	$(top_srcdir)/src/common/xsignal.c \
	$(top_srcdir)/src/common/xsignal.h

man_MANS = \
	mungekey.8
