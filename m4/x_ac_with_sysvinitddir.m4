###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_SYSVINITDDIR
#
#  DESCRIPTION:
#    The "--with-sysvinitddir" option sets "sysvinitddir", the installation
#    directory for SysV init scripts.
#
#    By default, sysvinitddir will be disabled/unset if systemdunitdir is set.
#    Otherwise, sysvinitddir will default to either "${sysconfdir}/rc.d/init.d"
#    or "${sysconfdir}/init.d" if that directory exists on the build system.
###############################################################################

AC_DEFUN([X_AC_WITH_SYSVINITDDIR],
[
  AC_REQUIRE([X_AC_WITH_SYSTEMDUNITDIR])
  AC_MSG_CHECKING([for sysvinitddir])
  AC_ARG_WITH(
    [sysvinitddir],
    [AS_HELP_STRING(
       [--with-sysvinitddir@<:@=DIR@:>@],
       [SysV init script installation directory])])
  AS_IF(
    [test "x${with_sysvinitddir}" = xyes \
       || (test "x${with_sysvinitddir}" = x && test "x${systemdunitdir}" = x)],
    [AS_IF(
       [test -d /etc/rc.d/init.d], [sysvinitddir='${sysconfdir}/rc.d/init.d'],
       [test -d /etc/init.d], [sysvinitddir='${sysconfdir}/init.d'])],
    [expr "x${with_sysvinitddir}" : "x\/" >/dev/null 2>&1],
    [sysvinitddir=${with_sysvinitddir}],
    [test "x${with_sysvinitddir}" != xno && test "x${with_sysvinitddir}" != x],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-sysvinitddir=${with_sysvinitddir}])])
  AS_IF(
    [test "x${sysvinitddir}" = x && test "x${with_sysvinitddir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([sysvinitddir requested but not found])])
  AC_SUBST([sysvinitddir])
  AC_MSG_RESULT([${sysvinitddir:-disabled}])
])
