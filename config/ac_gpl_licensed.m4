##*****************************************************************************
## $Id: ac_gpl_licensed.m4,v 1.2 2003/05/07 17:02:44 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    AC_GPL_LICENSED
#
#  DESCRIPTION:
#    Acknowledge being licensed under terms of the GNU General Public License.
##*****************************************************************************

AC_DEFUN([AC_GPL_LICENSED],
[
  AC_DEFINE([GPL_LICENSED], [1],
    [Define to 1 if licensed under terms of the GNU General Public License.]
  )
])
