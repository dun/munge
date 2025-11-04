###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_SYSTEMDSYSUSERSDIR
#
#  DESCRIPTION:
#    The "--with-systemdsysusersdir" option sets "systemdsysusersdir",
#    the installation directory for systemd-sysusers config files.
#
#    By default (or if this option is specified without a directory name),
#    systemdsysusersdir will be set to "${prefix}/lib/sysusers.d" if the
#    "/usr/lib/sysusers.d" directory exists on the build system.
###############################################################################

AC_DEFUN([X_AC_WITH_SYSTEMDSYSUSERSDIR],
[
  AC_MSG_CHECKING([for systemdsysusersdir])
  AC_ARG_WITH(
    [systemdsysusersdir],
    [AS_HELP_STRING(
       [--with-systemdsysusersdir@<:@=DIR@:>@],
       [systemd-sysusers config file installation directory])])
  AS_IF(
    [test "x${with_systemdsysusersdir}" = xyes \
       || test "x${with_systemdsysusersdir}" = x],
    [AS_IF(
       [test -d /usr/lib/sysusers.d],
       [systemdsysusersdir='${prefix}/lib/sysusers.d'])],
    [expr "x${with_systemdsysusersdir}" : "x\/" >/dev/null 2>&1],
    [systemdsysusersdir=${with_systemdsysusersdir}],
    [test "x${with_systemdsysusersdir}" != xno],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-systemdsysusersdir=${with_systemdsysusersdir}])])
  AS_IF(
    [test "x${systemdsysusersdir}" = x && test "x${with_systemdsysusersdir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([systemdsysusersdir requested but not found])])
  AC_SUBST([systemdsysusersdir])
  AC_MSG_RESULT([${systemdsysusersdir:-disabled}])
])
