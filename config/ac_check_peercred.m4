##*****************************************************************************
## $Id: ac_check_peercred.m4,v 1.1 2004/01/30 23:14:18 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    AC_CHECK_PEERCRED
#
#  DESCRIPTION:
#    Checks to see if the SO_PEERCRED socket option is supported.
##*****************************************************************************

AC_DEFUN([AC_CHECK_PEERCRED],
[
  AC_MSG_CHECKING([for SO_PEERCRED sockopt])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[#include <sys/types.h>
#include <sys/socket.h>]],
      [[getsockopt (0, SOL_SOCKET, SO_PEERCRED, 0, 0);]])],
    [AC_DEFINE([HAVE_SO_PEERCRED], [1],
      [Define to 1 if you have the SO_PEERCRED socket option.])
      ac_check_peercred=yes]
  )
  AC_MSG_RESULT([${ac_check_peercred=no}])
])
