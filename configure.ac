# MUNGE configure.ac
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

##
# Prologue.
##
AC_INIT
X_AC_META
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
X_AC_CANONICAL
X_AC_HUMOR
X_AC_EXPAND_INSTALL_DIRS

##
# Automake support.
##
AM_INIT_AUTOMAKE([$PACKAGE], [$VERSION])
AM_MAINTAINER_MODE

##
# Checks for programs.
##
AC_USE_SYSTEM_EXTENSIONS
X_AC_ARCH
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_SED
AM_PROG_CC_C_O
LT_INIT
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
# Checks for customizations.
##
X_AC_WITH_MUNGE_SOCKET

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
  t/Makefile \
)
AC_OUTPUT
