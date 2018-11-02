#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_AIX
#
#  DESCRIPTION:
#    Check for AIX platform-specific issues.
#******************************************************************************

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
