##*****************************************************************************
## $Id: configure.ac,v 1.26 2004/11/12 02:58:31 dun Exp $
##*****************************************************************************
## Process this file with autoconf to produce a configure script.
##*****************************************************************************
## This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
## For details, see <http://www.llnl.gov/linux/munge/>.
##
## Copyright (C) 2002-2004 The Regents of the University of California.
## Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## UCRL-CODE-155910.
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
AC_INIT([munge])
X_AC_META
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
X_AC_CANONICAL
X_AC_GPL_LICENSED
X_AC_HUMOR

##
# Automake support.
##
AM_INIT_AUTOMAKE([$PACKAGE], [$VERSION], [check-news dist-bzip2 gnu no-define])
AC_CONFIG_HEADERS([config/config.h])
AM_MAINTAINER_MODE

##
# Checks for programs.
##
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
X_AC_DEBUG

##
# Checks for libraries.
##
X_AC_CHECK_PTHREADS
X_AC_CHECK_COND_LIB(nsl, gethostbyname)
X_AC_CHECK_COND_LIB(socket, socket)
X_AC_CHECK_COND_LIB(bz2, BZ2_bzBuffToBuffCompress)
X_AC_CHECK_COND_LIB(z, compress)

##
# Checks for header files.
##
AC_HEADER_STDC
AC_CHECK_HEADERS( \
  bzlib.h \
  standards.h \
  zlib.h \
)

##
# Checks for typedefs, structures, and compiler characteristics.
##
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_UID_T
AC_CHECK_TYPES(socklen_t, [], [], [#include <sys/socket.h>])


##
# Checks for how to authenticate a non-parent process.
##
AC_CHECK_FUNCS(getpeereid)
X_AC_CHECK_PEERCRED
AC_CHECK_FILES(/dev/spx)
X_AC_CHECK_FIFO_RECVFD

##
# Checks for OpenSSL library functions.
#   Prevent libcrypto from being linked into all binaries.
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
AC_CHECK_TYPES(CRYPTO_dynlock, [], [], [#include <openssl/crypto.h>])

##
# Check for inet_ntop replacement.
#   Solaris needs libnsl here in order to perform this check.
##
ac_save_LIBS="$LIBS"
AC_CHECK_LIB(nsl, inet_ntop)
AC_REPLACE_FUNCS(inet_ntop)
LIBS="$ac_save_LIBS"

##
# Checks for library functions.
##
AC_CHECK_FUNCS( \
  localtime_r \
)
AC_REPLACE_FUNCS( \
  strlcat \
  strlcpy \
)

##
# Epilogue.
##
AC_CONFIG_FILES( \
  Makefile \
  src/Makefile \
  src/etc/Makefile \
  src/libcommon/Makefile \
  src/libcommon/munge.7 \
  src/libmissing/Makefile \
  src/libmunge/Makefile \
  src/libmunge/munge.3 \
  src/libmunge/munge_ctx.3 \
  src/munge/Makefile \
  src/munge/munge.1 \
  src/munge/remunge.1 \
  src/munge/unmunge.1 \
  src/munged/Makefile \
  src/munged/munged.8 \
)
AC_OUTPUT
