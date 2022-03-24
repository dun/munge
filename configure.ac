# MUNGE configure.ac
#
# This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
# For details, see <https://dun.github.io/munge/>.

##
# Prologue.
##
AC_PREREQ([2.61])
AC_INIT([MUNGE], m4_esyscmd([build-aux/gen-version]))
AC_SUBST([DATE], m4_esyscmd([build-aux/gen-date]))

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/libmunge/munge.h])
AC_REQUIRE_AUX_FILE([tap-driver.sh])

X_AC_WITH_MUNGE_SOCKET
X_AC_WITH_RUNSTATEDIR
X_AC_WITH_SYSTEMDUNITDIR
X_AC_WITH_SYSVINITDDIR
X_AC_WITH_SYSCONFIGDIR
X_AC_WITH_LOGROTATEDDIR
X_AC_WITH_PKGCONFIGDIR
X_AC_HUMOR

AM_INIT_AUTOMAKE([1.11 foreign dist-xz no-dist-gzip])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_USE_SYSTEM_EXTENSIONS
m4_ifdef([LT_INIT], [LT_INIT], [AC_PROG_LIBTOOL])

##
# Checks for programs.
##
X_AC_ARCH
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_SED
AM_PROG_CC_C_O
X_AC_DEBUG

##
# Checks for libraries.
##
X_AC_CHECK_PTHREADS
X_AC_CHECK_COND_LIB(bz2, BZ2_bzBuffToBuffCompress)
X_AC_CHECK_COND_LIB(rt, clock_gettime)
X_AC_CHECK_COND_LIB(z, compress)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)
m4_ifdef([AM_PATH_LIBGCRYPT], [AM_PATH_LIBGCRYPT])
X_AC_PATH_OPENSSL
X_AC_SELECT_CRYPTO_LIB
if test "${CRYPTO_PKG}" = "openssl"; then
  X_AC_CHECK_OPENSSL
fi

##
# Checks for header files.
##
AC_CHECK_HEADERS( \
  bzlib.h \
  ifaddrs.h \
  standards.h \
  sys/random.h \
  zlib.h \
)

##
# Checks for typedefs, structures, and compiler characteristics.
##
AC_C_CONST
AC_TYPE_UID_T
AC_CHECK_TYPES(socklen_t, [], [], [#include <sys/types.h>
#include <sys/socket.h>])

##
# Checks for library functions.
##
AC_CHECK_FUNCS( \
  clock_nanosleep \
  getentropy \
  getifaddrs \
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
  src/common/Makefile \
  src/etc/Makefile \
  src/libcommon/Makefile \
  src/libmissing/Makefile \
  src/libmunge/Makefile \
  src/libtap/Makefile \
  src/munge/Makefile \
  src/munged/Makefile \
  src/mungekey/Makefile \
  t/Makefile \
)
AC_OUTPUT
