#******************************************************************************
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
#    This macro must be placed after AC_CANONICAL_HOST and before
#    AC_PROG_CC or equivalent.
#
#  LIMITATIONS:
#    This macro doesn't begin to handle all of the various multiarch
#    permutations found in the wild.  So far, it's only been tested
#    on AIX & x86-64 Linux.
#******************************************************************************

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
  AC_MSG_RESULT([${x_ac_arch=no}])

  if test "$x_ac_arch" != "no"; then
    AC_MSG_CHECKING([whether $CC accepts -m${x_ac_arch}])
    _x_ac_arch_cflags_save="$CFLAGS"
    CFLAGS="$CFLAGS -m${x_ac_arch}"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
      [AS_VAR_SET(x_ac_arch_prog_cc_m, yes)],
      [AS_VAR_SET(x_ac_arch_prog_cc_m, no); CFLAGS="$_x_ac_arch_cflags_save"])
    AC_MSG_RESULT([${x_ac_arch_prog_cc_m=no}])

    if expr X"$host_os" : "Xaix" >/dev/null 2>&1; then
      AC_MSG_CHECKING([whether $CC accepts -maix${x_ac_arch}])
      _x_ac_arch_cflags_save="$CFLAGS"
      CFLAGS="$CFLAGS -maix${x_ac_arch}"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
        [AS_VAR_SET(x_ac_arch_prog_cc_maix, yes)],
        [AS_VAR_SET(x_ac_arch_prog_cc_maix, no); CFLAGS="$_x_ac_arch_cflags_save"])
      AC_MSG_RESULT([${x_ac_arch_prog_cc_maix=no}])
    fi
  fi

  if test "$x_ac_arch" = "32"; then
    if expr X"$host_os" : "Xaix" >/dev/null 2>&1; then
      test -z "$OBJECT_MODE" && AC_MSG_ERROR(
        [The OBJECT_MODE variable must be exported to the shell.])
      OBJECT_MODE=32
      AC_SUBST([OBJECT_MODE])
    else
      test -d /lib -o -d /usr/lib \
        && LDFLAGS="-L/lib -L/usr/lib $LDFLAGS"
    fi
  elif test "$x_ac_arch" = "64"; then
    if expr X"$host_os" : "Xaix" >/dev/null 2>&1; then
      test -z "$OBJECT_MODE" && AC_MSG_ERROR(
        [The OBJECT_MODE variable must be exported to the shell.])
      OBJECT_MODE=64
      AC_SUBST([OBJECT_MODE])
    else
      test -d /lib64 -o -d /usr/lib64 \
        && LDFLAGS="-L/lib64 -L/usr/lib64 $LDFLAGS"
    fi
  fi
  ]
)
