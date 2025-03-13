###############################################################################
# SYNOPSIS:
#   X_AC_SELECT_CRYPTO_LIB
#
# DESCRIPTION:
#   Select either the Libgcrypt or OpenSSL cryptographic library.
#   Define CRYPTO_CFLAGS, CRYPTO_LIBS, and CRYPTO_PKG accordingly.
#   Define either HAVE_LIBGCRYPT or HAVE_OPENSSL which are mutually-exclusive.
###############################################################################

AC_DEFUN_ONCE([X_AC_SELECT_CRYPTO_LIB],
[
  AC_REQUIRE([X_AC_WITH_LIBGCRYPT])
  AC_REQUIRE([X_AC_WITH_OPENSSL])

  AC_MSG_CHECKING([for cryptographic library selection])

  AC_ARG_WITH(
    [crypto-lib],
    [AS_HELP_STRING(
      [--with-crypto-lib=@{:@libgcrypt|openssl@:}@],
      [specify which cryptographic library to use])],
    [if test "${withval}" = openssl || test "${withval}" = libgcrypt; then
      CRYPTO_PKG="${withval}"
    else
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([invalid value "${withval}" for --with-crypto-lib])
    fi])

  if (test "${CRYPTO_PKG}" = openssl || test "x${CRYPTO_PKG}" = x) &&
      test "x${LIBCRYPTO_LIBS}" != x; then
    CRYPTO_CFLAGS="${LIBCRYPTO_CFLAGS}"
    CRYPTO_LIBS="${LIBCRYPTO_LIBS}"
    CRYPTO_PKG="openssl"
    AC_DEFINE([HAVE_OPENSSL], [1],
      [Define to 1 if you have the OpenSSL `crypto' library @{:@-lcrypto@:}@.])
  elif (test "${CRYPTO_PKG}" = libgcrypt || test "x${CRYPTO_PKG}" = x) &&
      test "x${LIBGCRYPT_LIBS}" != x; then
    CRYPTO_CFLAGS="${LIBGCRYPT_CFLAGS}"
    CRYPTO_LIBS="${LIBGCRYPT_LIBS}"
    CRYPTO_PKG="libgcrypt"
    AC_DEFINE([HAVE_LIBGCRYPT], [1],
      [Define to 1 if you have the Libgcrypt library @{:@-lgcrypt@:}@.])
  else
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([failed to locate cryptographic library])
  fi

  AC_SUBST([CRYPTO_CFLAGS])
  AC_SUBST([CRYPTO_LIBS])
  AC_SUBST([CRYPTO_PKG])
  AC_MSG_RESULT([${CRYPTO_PKG}])

  if test "${CRYPTO_PKG}" = openssl; then
    X_AC_CHECK_OPENSSL
  fi
])
