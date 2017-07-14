#******************************************************************************
# Process this file with autoconf to produce a configure script.
#******************************************************************************
# Written by Chris Dunlap <cdunlap@llnl.gov>.
# Copyright (C) 2007-2017 Lawrence Livermore National Security, LLC.
# Copyright (C) 2002-2007 The Regents of the University of California.
# UCRL-CODE-155910.
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.
#
# MUNGE is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.  Additionally for the MUNGE library (libmunge), you
# can redistribute it and/or modify it under the terms of the GNU Lesser
# General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# MUNGE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# and GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# and GNU Lesser General Public License along with MUNGE.  If not, see
# <http://www.gnu.org/licenses/>.
#******************************************************************************

##
# Prologue.
##
AC_INIT
X_AC_META
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
X_AC_CANONICAL
X_AC_HUMOR
X_AC_EXPAND_INSTALL_DIRS

##
# Automake support.
##
AM_INIT_AUTOMAKE([$PACKAGE], [$VERSION])
AC_CONFIG_HEADERS([config/config.h])
AM_MAINTAINER_MODE

##
# Checks for programs.
##
AC_USE_SYSTEM_EXTENSIONS
X_AC_ARCH
AC_PROG_CC
AM_PROG_CC_C_O
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
if test "${CRYPTO_PKG}" = "openssl"; then
  X_AC_CHECK_OPENSSL
fi

##
# Checks for header files.
##
AC_HEADER_STDC
AC_CHECK_HEADERS( \
  bzlib.h \
  standards.h \
  sys/random.h \
  zlib.h \
)

##
# Checks for typedefs, structures, and compiler characteristics.
##
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_UID_T
AC_CHECK_TYPES(socklen_t, [], [], [#include <sys/types.h>
#include <sys/socket.h>])

##
# Checks for library functions.
##
AC_CHECK_FUNCS( \
  getentropy \
  getrandom \
  localtime_r \
  mlockall \
  sysconf \
)
AC_REPLACE_FUNCS( \
  inet_ntop \
  strlcat \
  strlcpy \
)
X_AC_GETGRENT
X_AC_GETGRNAM
X_AC_GETPWNAM

##
# Checks for platform-specific issues.
##
X_AC_AIX
X_AC_DARWIN

##
# Checks for client authentication method.
##
X_AC_SELECT_AUTH_METHOD

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
  src/libmunge/munge_enum.3 \
  src/munge/Makefile \
  src/munge/munge.1 \
  src/munge/remunge.1 \
  src/munge/unmunge.1 \
  src/munged/Makefile \
  src/munged/munged.8 \
)
AC_OUTPUT
