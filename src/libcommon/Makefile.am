##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## Copyright (C) 2007-2013 Lawrence Livermore National Security, LLC.
## Copyright (C) 2002-2007 The Regents of the University of California.
## UCRL-CODE-155910.
##
## This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
## For details, see <https://munge.googlecode.com/>.
##
## MUNGE is free software: you can redistribute it and/or modify it under
## the terms of the GNU General Public License as published by the Free
## Software Foundation, either version 3 of the License, or (at your option)
## any later version.  Additionally for the MUNGE library (libmunge), you
## can redistribute it and/or modify it under the terms of the GNU Lesser
## General Public License as published by the Free Software Foundation,
## either version 3 of the License, or (at your option) any later version.
##
## MUNGE is distributed in the hope that it will be useful, but WITHOUT
## ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
## FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
## and GNU Lesser General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## and GNU Lesser General Public License along with MUNGE.  If not, see
## <http://www.gnu.org/licenses/>.
##*****************************************************************************

include $(top_srcdir)/config/Make-inc.mk

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
	posignal.c \
	posignal.h \
	str.c \
	str.h \
	version.c \
	version.h

man_MANS = \
	munge.7

install-data-local:
	$(INSTALL) -d -m 0755 "$(DESTDIR)$(mandir)/man7"
	chmod 755 "$(DESTDIR)$(mandir)"
