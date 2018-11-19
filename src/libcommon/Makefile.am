# MUNGE src/libcommon/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

TEMPLATE_FILES = \
	munge.7.in

SUBSTITUTE_FILES = \
	munge.7

EXTRA_DIST = \
	$(TEMPLATE_FILES)

CLEANFILES = \
	$(SUBSTITUTE_FILES)

$(SUBSTITUTE_FILES): Makefile
	$(AM_V_GEN)$(substitute) < "$(srcdir)/$@.in" > "$(builddir)/$@"

munge.7: munge.7.in

noinst_LTLIBRARIES = \
	libcommon.la

libcommon_la_CPPFLAGS = \
	-DDATE='"$(DATE)"' \
	-DLOCALSTATEDIR='"$(localstatedir)"' \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-I$(top_srcdir)/src/libmunge

libcommon_la_SOURCES = \
	common.h \
	fd.c \
	fd.h \
	license.c \
	license.h \
	log.c \
	log.h \
	m_msg.c \
	m_msg.h \
	munge_defs.h \
	str.c \
	str.h \
	version.c \
	version.h

# For dependencies on DATE.
#
$(srcdir)/libcommon_la-version.lo: Makefile

man_MANS = \
	munge.7
