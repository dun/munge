##*****************************************************************************
## $Id: x_ac_check_cond_lib.m4,v 1.2 2004/03/12 00:33:48 dun Exp $
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CHECK_COND_LIB(library, function)
#
#  DESCRIPTION:
#    Checks whether a program can be linked with <library> to get <function>.
#    Like AC_CHECK_LIB(), except that if the check succeeds, HAVE_LIB<library>
#    will be defined and a shell variable LIB<library> containing "-l<library>"
#    will be substituted via AC_SUBST().
#
#    In other words, this is just like the default action of AC_CHECK_LIB(),
#    except that instead of modifying LIBS (which will affect the linking of
#    all executables), the shell variable LIB<library> is defined so it can be
#    added to the linking of just those executables needing this library.
##*****************************************************************************

AC_DEFUN([X_AC_CHECK_COND_LIB],
[ AC_CHECK_LIB(
    [$1],
    [$2],
    [ AH_CHECK_LIB([$1])
      AS_TR_CPP([LIB$1])="-l$1";
      AC_SUBST(AS_TR_CPP([LIB$1]))
      AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_LIB$1]))
    ])
])
