##*****************************************************************************
## $Id: x_ac_humor.m4,v 1.2 2004/03/12 00:33:48 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_HUMOR
#
#  DESCRIPTION:
#    Check for random silliness.
##*****************************************************************************

AC_DEFUN([X_AC_HUMOR],
[ AC_CACHE_CHECK(
    [for a sense of humor],
    [x_ac_cv_humor],
    [
      x_ac_cv_humor=no
      true && x_ac_cv_humor=yes
    ])
])
