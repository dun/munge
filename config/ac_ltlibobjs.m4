##*****************************************************************************
## $Id: ac_ltlibobjs.m4,v 1.3 2003/05/07 18:58:12 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    AC_LTLIBOBJS
#
#  DESCRIPTION:
#    Adjust LIBOBJS for automake and/or libtool.
#    Refer to autoconf dox, section 15.6.4 (AC_LIBOBJ vs. LIBOBJS).
#
#  WARNINGS:
#    This macro must be placed after AC_REPLACE_FUNCS.
##*****************************************************************************

AC_DEFUN([AC_LTLIBOBJS],
[
  LIB@&t@OBJS=`echo "$LIB@&t@OBJS" | sed 's,\.[[^.]]* ,$U&,g;s,\.[[^.]]*$,$U&,'`
  LTLIBOBJS=`echo "$LIB@&t@OBJS" | sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`
  AC_SUBST([LTLIBOBJS])
])
