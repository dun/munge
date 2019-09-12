###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_RUNSTATEDIR
#
#  DESCRIPTION:
#    The "--with-runstatedir" option sets "runstatedir", the installation
#    directory for modifiable per-process data.  It is functionally equivalent
#    to the "--runstatedir" option (slated to appear in autoconf 2.70, and
#    backported to Debian's and Ubuntu's autoconf 2.69-9).  However,
#    "--with-runstatedir" will override "--runstatedir" if both are specified.
#
#    This option requires an absolute pathname for its directory argument.
#
#    If this option is not specified, runstatedir will default to
#    "${localstatedir}/run".
###############################################################################

AC_DEFUN([X_AC_WITH_RUNSTATEDIR],
[
  AC_MSG_CHECKING([for runstatedir])
  AC_ARG_WITH(
    [runstatedir],
    [AS_HELP_STRING(
       [--with-runstatedir=DIR],
       [modifiable per-process data installation directory @<:@LOCALSTATEDIR/run@:>@])])
  AS_IF(
    [test "x${with_runstatedir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([missing argument to --with-runstatedir])],
    [test "x${with_runstatedir}" = xno],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([illegal option --without-runstatedir])],
    [expr "x${with_runstatedir}" : "x\/" >/dev/null 2>&1],
    [runstatedir="${with_runstatedir}"],
    [test "x${with_runstatedir}" != x],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-runstatedir=${with_runstatedir}])])
  AS_IF(
    [test "x${runstatedir}" = x],
    [AC_SUBST([runstatedir], ['${localstatedir}/run'])])
  AC_MSG_RESULT([${runstatedir}])
])
