##*****************************************************************************
## $Id: x_ac_debug.m4,v 1.1 2004/03/05 20:04:18 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_DEBUG
#
#  DESCRIPTION:
#    Adds support for the "--enable-debug" configure script option.
#    If CFLAGS are not passed to configure, they will be set based
#    on whether debugging has been enabled.  Also, the NDEBUG macro
#    (used by assert) will be set accordingly.
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([X_AC_DEBUG],
[
  AC_MSG_CHECKING([whether debugging is enabled])
  AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [enable debugging code for development]),
      [ case "$enableval" in
          yes) x_ac_debug=yes ;;
          no)  x_ac_debug=no ;;
          *)   AC_MSG_RESULT([doh!])
               AC_MSG_ERROR([bad value "$enableval" for --enable-debug]) ;;
        esac ])
  if test "$x_ac_debug" = yes; then
    if test -z "$ac_save_CFLAGS"; then
      test "$ac_cv_prog_cc_g" = yes && _x_ac_debug_g="-g"
      test "$GCC" = yes && CFLAGS="-Wall -Werror $_x_ac_debug_g"
    fi
  else
    if test -z "$ac_save_CFLAGS"; then
      test "$GCC" = yes && CFLAGS="-O2 -Wall" || CFLAGS="-O"
    fi
    AC_DEFINE([NDEBUG], [1],
      [Define to 1 if you are building a production release.])
  fi
  AC_MSG_RESULT([${x_ac_debug=no}])
])
