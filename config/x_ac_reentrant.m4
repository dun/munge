##*****************************************************************************
## $Id: x_ac_reentrant.m4,v 1.1 2004/03/12 20:16:36 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_REENTRANT
#
#  DESCRIPTION:
#    Defines _REENTRANT.  For more information, refer to the LinuxThreads FAQ:
#      <http://pauillac.inria.fr/~xleroy/linuxthreads/faq.html#H>.
#    By defining it here, the define goes into "config.h" which the first
#      include (in my code, at least).
##*****************************************************************************

AC_DEFUN([X_AC_REENTRANT],
[ AC_DEFINE([_REENTRANT], [1],
    [Define to 1 if you are compiling multithreaded code.])
])
