###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_SYSTEMDUNITDIR
#
#  DESCRIPTION:
#    The "--with-systemdunitdir" option sets "systemdunitdir", the installation
#    directory for systemd service files.
#
#    By default (or if this option is specified without a directory name),
#    systemdunitdir will be set to "${prefix}/lib/systemd/system" if systemd
#    appears to be installed on the build system.
###############################################################################

AC_DEFUN([X_AC_WITH_SYSTEMDUNITDIR],
[
  AC_MSG_CHECKING([for systemdunitdir])
  AC_ARG_WITH(
    [systemdunitdir],
    [AS_HELP_STRING(
       [--with-systemdunitdir@<:@=DIR@:>@],
       [systemd service file installation directory])])
  AS_IF(
    [test "x${with_systemdunitdir}" = xyes \
       || test "x${with_systemdunitdir}" = x],
    [AS_IF(
       [systemctl --version >/dev/null 2>&1],
       [systemdunitdir='${prefix}/lib/systemd/system'])],
    [expr "x${with_systemdunitdir}" : "x\/" >/dev/null 2>&1],
    [systemdunitdir=${with_systemdunitdir}],
    [test "x${with_systemdunitdir}" != xno],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-systemdunitdir=${with_systemdunitdir}])])
  AS_IF(
    [test "x${systemdunitdir}" = x && test "x${with_systemdunitdir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([systemdunitdir requested but not found])])
  AC_SUBST([systemdunitdir])
  AC_MSG_RESULT([${systemdunitdir:-disabled}])
])
