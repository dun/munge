#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_DEBUG
#
#  DESCRIPTION:
#    Add support for the "--enable-debug" configure script option.  If enabled,
#    DEBUGCFLAGS will be set to debugging flags and appended to AM_CFLAGS.
#    The NDEBUG macro (used by assert) will also be set accordingly.
#
#  NOTES:
#    This macro must be placed after AC_PROG_CC or equivalent.
#******************************************************************************

AC_DEFUN([X_AC_DEBUG], [
  AC_MSG_CHECKING([whether debugging is enabled])
  AC_ARG_ENABLE(
    [debug],
    AS_HELP_STRING([--enable-debug], [enable debugging for code development]),
    [ case "$enableval" in
        yes) x_ac_debug=yes ;;
         no) x_ac_debug=no ;;
          *) AC_MSG_RESULT([failed])
             AC_MSG_ERROR([bad value "$enableval" for --enable-debug]) ;;
      esac
    ]
  )
  AS_IF(
    [test "AS_VAR_GET(x_ac_debug)" = yes],
    [
      AC_REQUIRE([AC_PROG_CC])

      # Clear configure's default CFLAGS when not explicitly set by user.
      AS_IF(
        [test -z "AS_VAR_GET(ac_env_CFLAGS_set)"],
        [CFLAGS=]
      )
      [DEBUGCFLAGS="$DEBUGCFLAGS -O0"]
      AS_IF(
        [test "AS_VAR_GET(ac_cv_prog_cc_g)" = yes],
        [DEBUGCFLAGS="$DEBUGCFLAGS -g"]
      )
      AS_IF(
        [test "AS_VAR_GET(GCC)" = yes],
        [DEBUGCFLAGS="$DEBUGCFLAGS -Wall -pedantic -std=c99"]
      )
      AM_CFLAGS="$AM_CFLAGS \$(DEBUGCFLAGS)"
      AC_SUBST([AM_CFLAGS])
      AC_SUBST([DEBUGCFLAGS])
    ],
    AC_DEFINE([NDEBUG], [1],
      [Define to 1 if you are building a production release.]
    )
  )
  AC_MSG_RESULT([${x_ac_debug=no}])
  ]
)
