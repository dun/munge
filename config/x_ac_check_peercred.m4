##*****************************************************************************
## $Id: x_ac_check_peercred.m4,v 1.4 2004/11/30 00:00:55 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CHECK_PEERCRED
#
#  DESCRIPTION:
#    Check to see if the SO_PEERCRED socket option is supported.
##*****************************************************************************

AC_DEFUN([X_AC_CHECK_PEERCRED], [
  AC_CACHE_CHECK(
    [for SO_PEERCRED sockopt],
    [x_ac_cv_check_peercred], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[

#include <sys/types.h>
#include <sys/socket.h>]], [[

getsockopt (0, SOL_SOCKET, SO_PEERCRED, 0, 0);]]

      )],
      AS_VAR_SET(x_ac_cv_check_peercred, yes),
      AS_VAR_SET(x_ac_cv_check_peercred, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_check_peercred) = yes],
    AC_DEFINE([HAVE_SO_PEERCRED], [1],
      [Define to 1 if you have the SO_PEERCRED socket option.]
    )
  )]
)
