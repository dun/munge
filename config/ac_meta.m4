##*****************************************************************************
## $Id: ac_meta.m4,v 1.2 2003/05/07 17:02:44 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    AC_META
#
#  DESCRIPTION:
#    Set PACKAGE and VERSION from the META file.
##*****************************************************************************

AC_DEFUN([AC_META],
[
  AC_MSG_CHECKING([metadata])

  PACKAGE="`perl -ne 'print,exit if s/^\s*NAME:\s*(\S*).*/\1/i' $srcdir/META`"
  AC_DEFINE_UNQUOTED([PACKAGE], ["$PACKAGE"], [Define the package name.])
  AC_SUBST([PACKAGE])

  VERSION="`perl -ne 'print,exit if s/^\s*VERSION:\s*(\S*).*/\1/i' $srcdir/META`"
  AC_DEFINE_UNQUOTED([VERSION], ["$VERSION"], [Define the package version.])
  AC_SUBST([VERSION])

  AC_MSG_RESULT([yes])
])
