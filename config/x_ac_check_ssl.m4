##*****************************************************************************
## $Id: x_ac_check_ssl.m4,v 1.2 2004/12/02 18:45:44 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CHECK_SSL()
#
#  DESCRIPTION:
#    Check the usual suspects for an OpenSSL installation,
#    updating CPPFLAGS and LDFLAGS as necessary.
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC and before AC_PROG_LIBTOOL.
##*****************************************************************************

AC_DEFUN([X_AC_CHECK_SSL], [

  _x_ac_check_ssl_dirs="/usr /usr/local /usr/local/openssl /opt/openssl /opt/freeware"

  AC_ARG_WITH(
    [ssl-dir],
    AS_HELP_STRING(
      [--with-ssl-dir=PATH],
      [Specify path to OpenSSL installation]),
    [_x_ac_check_ssl_dirs="$withval $_x_ac_check_ssl_dirs"])

  AC_CACHE_CHECK(
    [for OpenSSL installation],
    [x_ac_cv_check_ssl_dir],
    [
      for d in $_x_ac_check_ssl_dirs; do
        test -d "$d" || continue
        test -d "$d/include" || continue
        test -f "$d/include/openssl/evp.h" || continue
        test -d "$d/lib" || continue
        _x_ac_check_ssl_libs_save="$LIBS"
        LIBS="-lcrypto -L$d/lib $LIBS"
        AC_LINK_IFELSE(
          AC_LANG_CALL([], RAND_status),
          AS_VAR_SET(x_ac_cv_check_ssl_dir, $d))
        LIBS="$_x_ac_check_ssl_libs_save"
        test -n "$_x_ac_check_ssl_dir" && break
      done
    ])

  if test -z "$x_ac_cv_check_ssl_dir"; then
    AC_MSG_ERROR([unable to locate OpenSSL installation])
  fi

  if test "$x_ac_cv_check_ssl_dir" != "/usr"; then
    CPPFLAGS="$CPPFLAGS -I$x_ac_cv_check_ssl_dir/include"
    LDFLAGS="$LDFLAGS -L$x_ac_cv_check_ssl_dir/lib"
  fi

])
