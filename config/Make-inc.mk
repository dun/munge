##*****************************************************************************
## $Id$
##*****************************************************************************
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
## Copyright (C) 2002-2007 The Regents of the University of California.
## UCRL-CODE-155910.
##
## This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
## For details, see <http://munge.googlecode.com/>.
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

# Dependencies to ensure libraries get rebuilt.
#
$(top_builddir)/src/libcommon/libcommon.la \
$(top_builddir)/src/libmissing/libmissing.la \
$(top_builddir)/src/libmunge/libmunge.la \
: force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:

# Generic 'distclean' hook.
#
# The double-colon allows this target to be defined multiple times,
#   thereby allowing a Makefile.am to include its own distclean-local hook.
#
distclean-local::
	-rm -f *~ \#* .\#* cscope*.out core core.* tags TAGS
