# MUNGE src/libcommon/Makefile.am
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

include $(top_srcdir)/Make-inc.mk

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libmunge

noinst_LTLIBRARIES = \
	libcommon.la

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

man_MANS = \
	munge.7
