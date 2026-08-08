###############################################################################
# SYNOPSIS:
#   X_AC_DEBUG
#
# DESCRIPTION:
#   Add support for the "--enable-debug" configure option.  If enabled,
#   collect debugging flags in DEBUGCFLAGS and append them to AM_CFLAGS.
#   Otherwise define NDEBUG to disable assert() checks.
###############################################################################

AC_DEFUN([X_AC_DEBUG], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_MSG_CHECKING([whether debugging is enabled])
  AC_ARG_ENABLE(
    [debug],
    AS_HELP_STRING([--enable-debug], [enable debugging for code development]),
    [ case "${enableval}" in
        yes|no)
          x_ac_debug="${enableval}" ;;
        *)
          AC_MSG_RESULT([failed])
          AC_MSG_ERROR([bad value "${enableval}" for --enable-debug]) ;;
      esac ]
  )
  AS_IF(
    [test "x${x_ac_debug}" = xyes],
    [ # Clear configure's default CFLAGS when not explicitly set by user.
      AS_IF(
        [test "x${ac_env_CFLAGS_set}" = x],
        [CFLAGS=]
      )
      DEBUGCFLAGS="${DEBUGCFLAGS} -O0"
      AS_IF(
        [test "x${ac_cv_prog_cc_g}" = xyes],
        [DEBUGCFLAGS="${DEBUGCFLAGS} -g"]
      )
      AS_IF(
        [test "x${GCC}" = xyes],
        [DEBUGCFLAGS="${DEBUGCFLAGS} -std=c99 -pedantic -Wall"]
      )
      AM_CFLAGS="${AM_CFLAGS} \$(DEBUGCFLAGS)"
      AC_SUBST([AM_CFLAGS])
      AC_SUBST([DEBUGCFLAGS]) ],
    [ # Debugging not enabled.
      AC_DEFINE(
        [NDEBUG], [1],
        [Define to 1 if you are building a production release.]
      ) ]
  )
  AC_MSG_RESULT([${x_ac_debug=no}]) ]
)
