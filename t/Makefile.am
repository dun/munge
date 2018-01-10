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

TEST_EXTENSIONS = .t

T_LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/config/tap-driver.sh

TESTS = \
	0000-sharness.t \
	0001-env-vars.t \
	0010-basic.t \
	0011-munged-cmdline.t \
	0012-munge-cmdline.t \
	0013-unmunge-cmdline.t \
	0021-munged-valgrind.t \
	0022-munge-valgrind.t \
	0023-unmunge-valgrind.t \
	0100-munged-lock.t

EXTRA_DIST = \
	$(TESTS) \
	sharness.d \
	sharness.sh \
	test-terminal.perl \
	valgrind.supp

clean-local:
	-rm -rf test-results
	-rm -rf trash-directory.*
