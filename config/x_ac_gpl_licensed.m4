##*****************************************************************************
## $Id: x_ac_gpl_licensed.m4,v 1.3 2004/05/01 05:22:27 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_GPL_LICENSED
#
#  DESCRIPTION:
#    Acknowledge being licensed under terms of the GNU General Public License.
##*****************************************************************************

AC_DEFUN([X_AC_GPL_LICENSED], [
  AC_DEFINE([GPL_LICENSED], [1],
    [Define to 1 if licensed under terms of the GNU General Public License.]
  )]
)
