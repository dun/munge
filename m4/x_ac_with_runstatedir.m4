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
  AS_IF(
    [test "x${with_runstatedir}" = xyes],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([missing argument to --with-runstatedir])
    ],
    [test "x${with_runstatedir}" = xno],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([invalid option --without-runstatedir])
    ],
    [expr "x${with_runstatedir}" : "x\/" >/dev/null 2>&1],
    [runstatedir="${with_runstatedir}"],
    [test "x${with_runstatedir}" != x],
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
