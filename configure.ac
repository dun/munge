##*****************************************************************************
## $Id: configure.ac,v 1.3 2002/12/20 23:21:58 dun Exp $
##*****************************************************************************
## Process this file with autoconf to produce a configure script.
##*****************************************************************************
## Copyright (C) 2002-2003 The Regents of the University of California.
## Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## UCRL-CODE-2003-???.
## 
## This file is part of Munge, an authentication library.
## For details, see <http://www.llnl.gov/linux/munge/>.
## 
## Munge is free software; you can redistribute it and/or modify it under
## the terms of the GNU General Public License as published by the Free
## Software Foundation; either version 2 of the License, or (at your option)
## any later version.
## 
## Munge is distributed in the hope that it will be useful, but WITHOUT ANY
## WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
## FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
## details.
## 
## You should have received a copy of the GNU General Public License along
## with Munge; if not, write to the Free Software Foundation, Inc.,
## 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
##*****************************************************************************

##
# Prologue.
##
AC_INIT([munge], [0.0], [cdunlap@llnl.gov])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
AC_CANONICAL_SYSTEM
AC_HUMOR

##
# Automake support.
##
AM_INIT_AUTOMAKE([check-news dist-bzip2 gnu])
AM_CONFIG_HEADER([config/config.h])
AM_MAINTAINER_MODE

##
# Read META information.
##
#NAME="`perl -ne 'print,exit if s/^\s*NAME:\s*(\S*).*/\1/i' $srcdir/META`"
#AC_DEFINE_UNQUOTED([NAME], ["$NAME"], [Define the project's name.])
#AC_SUBST([NAME])

##
# Checks for programs.
##
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

##
# Checks for libraries.
##

##
# Checks for header files.
##
AC_HEADER_STDC
AC_CHECK_HEADERS( \
  errno.h \
  stdlib.h \
  string.h \
  unistd.h \
)

##
# Checks for typedefs, structures, and compiler characteristics.
##
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_UID_T

##
# Checks for library functions.
##
AC_FUNC_MALLOC
AC_CHECK_FUNCS( \
  strchr \
)

##
# Epilogue.
##
AC_CONFIG_FILES( \
  Makefile \
  src/Makefile \
  src/libmunge/Makefile \
  src/munged/Makefile \
)
AC_OUTPUT
