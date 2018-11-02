##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## Copyright (C) 2007-2018 Lawrence Livermore National Security, LLC.
## Copyright (C) 2002-2007 The Regents of the University of California.
## UCRL-CODE-155910.
##
## This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
## For details, see <https://dun.github.io/munge/>.
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

ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = dist-xz foreign no-dist-gzip

CONFIG_STATUS_DEPENDENCIES = META

SUBDIRS = \
	src \
	t

EXTRA_DIST = \
	.gitignore \
	AUTHORS \
	COPYING \
	COPYING.LESSER \
	DISCLAIMER.LLNS \
	DISCLAIMER.UC \
	HISTORY \
	INSTALL \
	JARGON \
	KEYS \
	META \
	NEWS \
	PLATFORMS \
	QUICKSTART \
	README \
	README.AIX \
	README.MULTILIB \
	THANKS \
	TODO \
	bootstrap \
	doc \
	extra \
	munge.spec

DISTCLEANFILES = \
	config/*~ \
	$(PACKAGE)-*.tar*

MAINTAINERCLEANFILES = \
	Makefile.in \
	aclocal.m4 \
	build-aux/compile \
	build-aux/config.guess \
	build-aux/config.sub \
	build-aux/depcomp \
	build-aux/install-sh \
	build-aux/ltmain.sh \
	build-aux/missing \
	build-aux/tap-driver.sh \
	build-aux/test-driver \
	config/config.h.in \
	configure \
	m4/libtool.m4 \
	m4/ltoptions.m4 \
	m4/ltsugar.m4 \
	m4/ltversion.m4 \
	m4/lt~obsolete.m4 \
	src/Makefile.in \
	src/etc/Makefile.in \
	src/libcommon/Makefile.in \
	src/libmissing/Makefile.in \
	src/libmunge/Makefile.in \
	src/munge/Makefile.in \
	src/munged/Makefile.in \
	t/Makefile.in
