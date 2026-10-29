###############################################################################
# SYNOPSIS:
#   X_AC_WITH_RUNSTATEDIR
#
# DESCRIPTION:
#   The "--with-runstatedir" option sets "runstatedir", the installation
#   directory for modifiable per-process data.  It is equivalent to the
#   "--runstatedir" option, which autoconf added in 2.70 and which Debian
#   and Ubuntu backported to autoconf 2.69-9.  "--with-runstatedir" wins
#   if both are given.
#
#   This option requires an absolute directory name for its argument.
#
#   If neither option is given, runstatedir defaults to "${localstatedir}/run".
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_RUNSTATEDIR], [
  AC_MSG_CHECKING([for runstatedir])
  AC_ARG_WITH(
    [runstatedir],
    [AS_HELP_STRING(
      [--with-runstatedir=DIR],
      [modifiable per-process data installation directory
        @<:@LOCALSTATEDIR/run@:>@]
    )]dnl
  )
  # Dispatch on "=VALUE" so that an empty argument differs from no option.
  AS_CASE(
    ["${with_runstatedir+=}${with_runstatedir}"],
    [=yes],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([missing argument to --with-runstatedir])
    ],
    [=no],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([invalid option --without-runstatedir])
    ],
    [=/*],
    [runstatedir="${with_runstatedir}"],
    [=*],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR(
        [m4_normalize(
          [expected an absolute directory name for
            --with-runstatedir=${with_runstatedir}]
        )])
    ]
  )
  AS_IF(
    [test "x${runstatedir}" = x],
    [AC_SUBST([runstatedir], ['${localstatedir}/run'])]
  )
  AC_MSG_RESULT([${runstatedir}])
])
