#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CHECK_LOCAL_PEERCRED
#
#  DESCRIPTION:
#    Check to see if the LOCAL_PEERCRED socket option is supported.
#******************************************************************************

AC_DEFUN([X_AC_CHECK_LOCAL_PEERCRED], [
  AC_CACHE_CHECK(
    [for LOCAL_PEERCRED sockopt],
    [x_ac_cv_check_local_peercred], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
]],
[[
getsockopt (0, 0, LOCAL_PEERCRED, 0, 0); ]]
      )],
      AS_VAR_SET(x_ac_cv_check_local_peercred, yes),
      AS_VAR_SET(x_ac_cv_check_local_peercred, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_check_local_peercred) = yes],
    AC_DEFINE([HAVE_LOCAL_PEERCRED], [1],
      [Define to 1 if you have the LOCAL_PEERCRED socket option.]
    )
  )]
)
