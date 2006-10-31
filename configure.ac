##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with autoconf to produce a configure script.
##*****************************************************************************
## Copyright (C) 2002-2006 The Regents of the University of California.
## Produced at Lawrence Livermore National Laboratory.
## Written by Chris Dunlap <cdunlap@llnl.gov>.
## UCRL-CODE-155910.
##
## This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
## For details, see <http://home.gna.org/munge/>.
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
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
##*****************************************************************************

##
# Prologue.
##
AC_INIT
X_AC_META
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
X_AC_CANONICAL
X_AC_GPL_LICENSED
X_AC_HUMOR
X_AC_EXPAND_INSTALL_DIRS

##
# Automake support.
##
AM_INIT_AUTOMAKE([$PACKAGE], [$VERSION], [check-news dist-bzip2 gnu no-define])
AC_CONFIG_HEADERS([config/config.h])
AM_MAINTAINER_MODE

##
# Checks for programs.
##
X_AC_ARCH
AC_PROG_CC
LT_INIT
AC_PROG_MAKE_SET
X_AC_DEBUG

##
# Checks for libraries.
##
X_AC_CHECK_PTHREADS
X_AC_CHECK_COND_LIB(bz2, BZ2_bzBuffToBuffCompress)
X_AC_CHECK_COND_LIB(z, compress)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)
AM_PATH_LIBGCRYPT
X_AC_PATH_OPENSSL
X_AC_SELECT_CRYPTO_LIB

##
# Checks for OpenSSL.
##
if test "$CRYPTO_PKG" = "openssl"; then
  ac_save_LIBS="$LIBS"
  LIBS="$LIBS $OPENSSL_LIBS"
  AC_CHECK_FUNCS( \
    ERR_error_string_n \
    EVP_CipherInit_ex \
    EVP_DigestInit_ex \
    EVP_aes_128_cbc \
    EVP_aes_256_cbc \
    EVP_sha256 \
    HMAC_Init_ex \
  )
  LIBS="$ac_save_LIBS"
  AC_CHECK_TYPES(CRYPTO_dynlock, [], [], [#include <openssl/crypto.h>])
fi

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
# Checks for how to authenticate a client process.
##
AC_CHECK_FUNCS(getpeereid)
AC_CHECK_FUNCS(getpeerucred)
AC_CHECK_HEADERS(ucred.h)
X_AC_CHECK_PEERCRED
AC_CHECK_FILES(/dev/spx)
X_AC_CHECK_FIFO_RECVFD

##
# Checks for library functions.
##
AC_CHECK_FUNCS( \
  localtime_r \
)
AC_REPLACE_FUNCS( \
  inet_ntop \
  strlcat \
  strlcpy \
)

##
# Check for platform-specific issues.
##
X_AC_AIX
X_AC_DARWIN

##
# Epilogue.
##
AC_CONFIG_FILES( \
  Makefile \
  src/Makefile \
  src/etc/Makefile \
  src/etc/munge.init \
  src/libcommon/Makefile \
  src/libcommon/munge.7 \
  src/libmissing/Makefile \
  src/libmunge/Makefile \
  src/libmunge/munge.3 \
  src/libmunge/munge_ctx.3 \
  src/libmunge/munge_enum.3 \
  src/munge/Makefile \
  src/munge/munge.1 \
  src/munge/remunge.1 \
  src/munge/unmunge.1 \
  src/munged/Makefile \
  src/munged/munged.8 \
)
AC_OUTPUT
