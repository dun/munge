###############################################################################
# SYNOPSIS:
#   X_AC_WITH_SYSTEMDUNITDIR
#
# DESCRIPTION:
#   The "--with-systemdunitdir" option sets "systemdunitdir", the installation
#   directory for systemd service files.
#
#   This option requires an absolute directory name for its argument.
#
#   By default (or if this option is specified without a directory name),
#   systemdunitdir will be set to "${prefix}/lib/systemd/system" if systemd
#   appears to be installed on the build system.  A bare
#   "--with-systemdunitdir" fails if systemd does not appear to be
#   installed.
#
#   Specifying "--without-systemdunitdir" disables it.
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_SYSTEMDUNITDIR], [
  AC_MSG_CHECKING([for systemdunitdir])
  AC_ARG_WITH(
    [systemdunitdir],
    [AS_HELP_STRING(
      [--with-systemdunitdir@<:@=DIR@:>@],
      [systemd service file installation directory]
    )]dnl
  )
  systemdunitdir=
  AS_CASE(
    ["${with_systemdunitdir}"],
    [yes|""],
    [
      AS_IF(
        [systemctl --version >/dev/null 2>&1],
        [systemdunitdir='${prefix}/lib/systemd/system']
      )
    ],
    [/*],
    [systemdunitdir="${with_systemdunitdir}"],
    [no],
    [],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR(
        [m4_normalize(
          [expected an absolute directory name for
            --with-systemdunitdir=${with_systemdunitdir}]
        )])
    ]
  )
  AS_IF(
    [test "x${systemdunitdir}" = x && test "x${with_systemdunitdir}" = xyes],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([systemdunitdir requested but not found])
    ]
  )
  AC_SUBST([systemdunitdir])
  AC_MSG_RESULT([${systemdunitdir:-disabled}])
])
