##*****************************************************************************
## $Id: configure.ac,v 1.8 2003/04/30 21:23:23 dun Exp $
##*****************************************************************************
## Process this file with autoconf to produce a configure script.
##*****************************************************************************
## This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
## For details, see <http://www.llnl.gov/linux/munge/>.
## UCRL-CODE-2003-???.
##
## Copyright (C) 2002-2003 The Regents of the University of California.
## Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
## Written by Chris Dunlap <cdunlap@llnl.gov>.
##
## This is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This is distributed in the hope that it will be useful, but WITHOUT
## ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
## FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
## for more details.
##
## You should have received a copy of the GNU General Public License;
## if not, write to the Free Software Foundation, Inc., 59 Temple Place,
## Suite 330, Boston, MA  02111-1307  USA.
##*****************************************************************************

##
# Prologue.
##
AC_INIT([munge], [0.1], [cdunlap@llnl.gov])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
AC_CANONICAL_SYSTEM
AC_GPL_LICENSED
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
  getopt.h \
)

##
# Checks for typedefs, structures, and compiler characteristics.
##
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_UID_T
AC_CHECK_TYPES(CRYPTO_dynlock, [], [], [#include <openssl/crypto.h>])

##
# Checks for OpenSSL library functions.
##
ac_save_LIBS="$LIBS"
AC_CHECK_LIB(crypto, RAND_bytes)
AC_CHECK_FUNCS( \
  ERR_error_string_n \
  EVP_CipherInit_ex \
  EVP_DigestInit_ex \
  EVP_aes_128_cbc \
  HMAC_Init_ex \
)
LIBS="$ac_save_LIBS"

##
# Checks for Pthreads
##
ac_save_LIBS="$LIBS"
AC_CHECK_LIB(pthread, pthread_create)
LIBS="$ac_save_LIBS"

##
# Checks for library functions.
##
#AC_FUNC_MALLOC
AC_CHECK_FUNCS( \
  getopt_long \
  localtime_r \
)
AC_REPLACE_FUNCS( \
  strlcat \
  strlcpy \
)
AC_LTLIBOBJS

##
# Epilogue.
##
AC_CONFIG_FILES( \
  Makefile \
  src/Makefile \
  src/etc/Makefile \
  src/libcommon/Makefile \
  src/libmissing/Makefile \
  src/libmunge/Makefile \
  src/munge/Makefile \
  src/munged/Makefile \
)
AC_OUTPUT
