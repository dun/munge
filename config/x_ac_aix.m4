##*****************************************************************************
## $Id: x_ac_aix.m4,v 1.1 2004/11/24 19:05:15 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_AIX
#
#  DESCRIPTION:
#    Check for AIX platform-specific issues.
##*****************************************************************************

AC_DEFUN([X_AC_AIX], [
  case "$host" in
    *-*-aix*)
      LDFLAGS="$LDFLAGS -Wl,-brtl"      # enable run-time linking
      ;;
    *)
      ;;
  esac
  ]
)
