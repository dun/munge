###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_SYSCONFIGDIR
#
#  DESCRIPTION:
#    The "--with-sysconfigdir" option sets "sysconfigdir", the installation
#    directory for systemd/sysvinit system configuration files.
#
#    By default (or if this option is specified without a directory name),
#    sysconfigdir will be set to either "${sysconfdir}/sysconfig" or
#    "${sysconfdir}/default" if the corresponding subdirectory exists in /etc
#    on the build system.
###############################################################################

AC_DEFUN([X_AC_WITH_SYSCONFIGDIR],
[
  AC_MSG_CHECKING([for sysconfigdir])
  AC_ARG_WITH(
    [sysconfigdir],
    [AS_HELP_STRING(
       [--with-sysconfigdir@<:@=DIR@:>@],
       [systemd/sysvinit config file installation directory])])
  AS_IF(
    [test "x${with_sysconfigdir}" = xyes \
       || test "x${with_sysconfigdir}" = x],
    [AS_IF(
       [test -d /etc/sysconfig], [sysconfigdir='${sysconfdir}/sysconfig'],
       [test -d /etc/default], [sysconfigdir='${sysconfdir}/default'])],
    [expr "x${with_sysconfigdir}" : "x\/" >/dev/null 2>&1],
    [sysconfigdir=${with_sysconfigdir}],
    [test "x${with_sysconfigdir}" != xno],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-sysconfigdir=${with_sysconfigdir}])])
  AS_IF(
    [test "x${sysconfigdir}" = x && test "x${with_sysconfigdir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([sysconfigdir requested but not found])])
  AC_SUBST([sysconfigdir])
  AC_MSG_RESULT([${sysconfigdir:-disabled}])
])
