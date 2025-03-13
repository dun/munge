###############################################################################
# SYNOPSIS:
#   X_AC_WITH_OPENSSL
#
# DESCRIPTION:
#   Check for the OpenSSL libcrypto library.  Use pkgconf if available.
#   Allow LIBCRYPTO_CFLAGS and LIBCRYPTO_LIBS to be manually specified.
#   Define LIBCRYPTO_CFLAGS and LIBCRYPTO_LIBS accordingly.
#
# USAGE:
#   --with-openssl-prefix (or option not specified)
#     check with pkgconf; if not found, check in the standard path
#   --with-openssl-prefix=/path
#     ignore pkgconf and check in the specified absolute path
#   --without-openssl-prefix
#     do not check
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_OPENSSL],
[
  AC_REQUIRE([AC_PROG_CC])
  AC_ARG_WITH([openssl-prefix],
    [AS_HELP_STRING([--with-openssl-prefix=PATH],
      [prefix where OpenSSL is installed])])

  have_libcrypto=
  openssl_prefix=

  if test "x${withval}" != xno; then
    if test "x${withval}" = xyes || test "x${withval}" = x; then
      m4_ifdef(
        [PKG_CHECK_MODULES],
        [PKG_CHECK_MODULES(
          [LIBCRYPTO], [libcrypto], [have_libcrypto=yes], [:])],
        [:])
    elif expr match "${withval}" "[[^/]]" >/dev/null; then
      AC_MSG_ERROR([invalid value "${withval}" for --with-openssl-prefix])
    else
      openssl_prefix="${withval}"
    fi

    if test "x${have_libcrypto}" != xyes; then
      AC_MSG_CHECKING([for libcrypto])
      openssl_cflags=
      openssl_libs="-lcrypto"
      if test "x${openssl_prefix}" != x; then
        openssl_cflags="-I${openssl_prefix}/include ${openssl_cflags}"
        openssl_libs="-L${openssl_prefix}/lib ${openssl_libs}"
      fi
      openssl_cflags_save="${CFLAGS}"
      openssl_libs_save="${LIBS}"
      CFLAGS="${openssl_cflags} ${CFLAGS}"
      LIBS="${openssl_libs} ${LIBS}"
      AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
          [[#include <openssl/rand.h>]],
          [[(void) RAND_bytes (NULL, 0);]])],
        [ LIBCRYPTO_CFLAGS="${openssl_cflags}"
          LIBCRYPTO_LIBS="${openssl_libs}"
          have_libcrypto=yes])
      CFLAGS="${openssl_cflags_save}"
      LIBS="${openssl_libs_save}"
      AC_MSG_RESULT([${have_libcrypto:=no}])
    fi
  fi

  AC_SUBST([LIBCRYPTO_CFLAGS])
  AC_SUBST([LIBCRYPTO_LIBS])
  if test "x${LIBCRYPTO_LIBS}" = x && test "x${withval}" = xyes; then
    AC_MSG_FAILURE([failed to configure --with-openssl-prefix])
  fi
])
