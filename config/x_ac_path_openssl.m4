#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_PATH_OPENSSL
#
#  DESCRIPTION:
#    Search the usual suspects for an OpenSSL installation.
#    If found, set the makefile variables OPENSSL_CFLAGS and OPENSSL_LIBS.
#
#  NOTES:
#    The $x_ac_path_openssl_prefix result is not cached since the selected
#    OpenSSL installation should be based on the specified 32-bit or 64-bit
#    architecture.
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC.
#******************************************************************************

AC_DEFUN([X_AC_PATH_OPENSSL], [
  AC_MSG_CHECKING([for OpenSSL installation])

  _x_ac_path_openssl_dirs="/usr /usr/local /usr/local/openssl* /usr/sfw /opt /opt/openssl* /opt/freeware /opt/freeware/openssl*"

  AC_ARG_WITH(
    [openssl-prefix],
    AS_HELP_STRING(
      [--with-openssl-prefix=PATH],
      [specify path to OpenSSL installation]),
    [
      test "$withval" = "no" \
        && x_ac_path_openssl_prefix="no" \
        || _x_ac_path_openssl_dirs="$withval $_x_ac_path_openssl_dirs"
    ])

  if test "$x_ac_path_openssl_prefix" != "no"; then
    x_ac_path_openssl_prefix="no"
    for d in $_x_ac_path_openssl_dirs; do
      test -d "$d" || continue
      test -d "$d/include" || continue
      test -f "$d/include/openssl/evp.h" || continue
      test -d "$d/lib" || continue
      _x_ac_path_openssl_libs_save="$LIBS"
      LIBS="-L$d/lib -lcrypto $LIBS"
      AC_LINK_IFELSE(
        [AC_LANG_CALL([], RAND_status)],
        x_ac_path_openssl_prefix="$d")
      LIBS="$_x_ac_path_openssl_libs_save"
      test "$x_ac_path_openssl_prefix" != "no" && break
    done
  fi

  if test "$x_ac_path_openssl_prefix" != "no"; then
    OPENSSL_CFLAGS=""
    OPENSSL_LIBS="-lcrypto"
    if test "$x_ac_path_openssl_prefix" != "/usr"; then
      OPENSSL_CFLAGS="-I$x_ac_path_openssl_prefix/include $OPENSSL_CFLAGS"
      OPENSSL_LIBS="-L$x_ac_path_openssl_prefix/lib $OPENSSL_LIBS"
    fi
    AC_SUBST([OPENSSL_CFLAGS])
    AC_SUBST([OPENSSL_LIBS])
  fi

  AC_MSG_RESULT([$x_ac_path_openssl_prefix])
])
