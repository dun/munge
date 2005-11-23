##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_ARCH
#
#  DESCRIPTION:
#    Add support for the "--enable-arch=n" configure script option.
#    This option can be set to either 32 or 64 in order to specify whether
#    code should be generated for a 32-bit or 64-bit architecture.
#
#  WARNINGS:
#    This macro must be placed before AC_PROG_CC or equivalent.
#
#  LIMITATIONS:
#    This macro doesn't begin to handle the various multiarch permutations
#    found in the wild.
##*****************************************************************************

AC_DEFUN([X_AC_ARCH], [
  AC_MSG_CHECKING([for specified code architecture])
  AC_ARG_ENABLE(
    [arch],
    AS_HELP_STRING([--enable-arch=n], [specify either a 32 or 64 bit arch]),
    [ case "$enableval" in
        32) x_ac_arch=$enableval ;;
        64) x_ac_arch=$enableval ;;
         *) AC_MSG_RESULT([specify either 32 or 64])
            AC_MSG_ERROR([bad value "$enableval" for --enable-arch]) ;;
      esac
    ]
  )
  if test "$x_ac_arch" == "32"; then
    CFLAGS="$CFLAGS -m32"
    LDFLAGS="-L/lib -L/usr/lib $LDFLAGS"
  elif test "$x_ac_arch" == "64"; then
    CFLAGS="$CFLAGS -m64"
    LDFLAGS="-L/lib64 -L/usr/lib64 $LDFLAGS"
  fi
  AC_MSG_RESULT([${x_ac_arch=no}])
  ]
)
