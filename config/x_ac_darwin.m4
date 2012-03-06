#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_DARWIN
#
#  DESCRIPTION:
#    Check for Darwin platform-specific issues.
#
#    A different version of certain pthread routines is used when
#    _APPLE_C_SOURCE is defined.  Without it, pthread_cond_wait() is not
#    recognized as a cancellation point.
#******************************************************************************

AC_DEFUN([X_AC_DARWIN], [
  case "$host" in
    *-*-darwin*)
      AC_DEFINE([_APPLE_C_SOURCE], [1],
        [Define to 1 if you are building on Darwin (Mac OS X).]
      )
      ;;
    *)
      ;;
  esac
  ]
)
