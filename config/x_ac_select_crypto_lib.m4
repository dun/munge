#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_SELECT_CRYPTO_LIB
#
#  DESCRIPTION:
#    Select either the Libgcrypt or OpenSSL cryptographic library,
#      or throw a fatal error.
#    Define either HAVE_LIBGCRYPT or HAVE_OPENSSL.
#    Set the makefile variables CRYPTO_CFLAGS, CRYPTO_LIBS, and CRYPTO_PKG.
#
#  NOTES:
#    The HAVE_LIBGCRYPT and HAVE_OPENSSL defs are mutually-exclusive.
#
#  WARNINGS:
#    This macro must be placed after AM_PATH_LIBGCRYPT and X_AC_PATH_OPENSSL.
#******************************************************************************

AC_DEFUN([X_AC_SELECT_CRYPTO_LIB], [
  AC_MSG_CHECKING([which cryptographic library to use])

  AC_ARG_WITH(
    [crypto-lib],
    AS_HELP_STRING(
      [--with-crypto-lib=(libgcrypt|openssl)],
      [specify which cryptographic library to use]),
    [
      case "$withval" in
        libgcrypt) CRYPTO_PKG="libgcrypt" ;;
        openssl)   CRYPTO_PKG="openssl" ;;
        *) AC_MSG_RESULT([specify either "libgcrypt" or "openssl"])
           AC_MSG_ERROR([bad value "$withval" for --with-crypto-lib]) ;;
      esac
    ])

  if test -n "$OPENSSL_LIBS" -a \
      \( "$CRYPTO_PKG" = "openssl" -o -z "$CRYPTO_PKG" \) ; then
    CRYPTO_CFLAGS="$OPENSSL_CFLAGS"
    CRYPTO_LIBS="$OPENSSL_LIBS"
    CRYPTO_PKG="openssl"
    AC_DEFINE([HAVE_OPENSSL], [1],
      [Define to 1 if you want to use the OpenSSL cryptographic library.])
  elif test -n "$LIBGCRYPT_LIBS" -a \
      \( "$CRYPTO_PKG" = "libgcrypt" -o -z "$CRYPTO_PKG" \) ; then
    CRYPTO_CFLAGS="$LIBGCRYPT_CFLAGS"
    CRYPTO_LIBS="$LIBGCRYPT_LIBS"
    CRYPTO_PKG="libgcrypt"
    AC_DEFINE([HAVE_LIBGCRYPT], [1],
      [Define to 1 if you want to use the Libgcrypt cryptographic library.])
  else
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([unable to locate cryptographic library])
  fi

  AC_SUBST([CRYPTO_CFLAGS])
  AC_SUBST([CRYPTO_LIBS])
  AC_SUBST([CRYPTO_PKG])

  AC_MSG_RESULT([$CRYPTO_PKG])
])
