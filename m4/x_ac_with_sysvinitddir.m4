###############################################################################
# SYNOPSIS:
#   X_AC_WITH_SYSVINITDDIR
#
# DESCRIPTION:
#   The "--with-sysvinitddir" option sets "sysvinitddir", the installation
#   directory for sysvinit scripts.
#
#   This option requires an absolute directory name for its argument.
#
#   By default, sysvinitddir will be disabled/unset if systemdunitdir is set.
#   Otherwise, sysvinitddir will default to either "${sysconfdir}/rc.d/init.d"
#   or "${sysconfdir}/init.d" if that directory exists on the build system.
#   A bare "--with-sysvinitddir" looks for that directory even when
#   systemdunitdir is set, and fails if neither directory exists.
#
#   Specifying "--without-sysvinitddir" also disables it.
#
#   Require X_AC_WITH_SYSTEMDUNITDIR.  The default above reads
#   "systemdunitdir", which that macro assigns, so it has to run first.
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_SYSVINITDDIR], [
  AC_REQUIRE([X_AC_WITH_SYSTEMDUNITDIR])[]dnl
  AC_MSG_CHECKING([for sysvinitddir])
  AC_ARG_WITH(
    [sysvinitddir],
    [AS_HELP_STRING(
      [--with-sysvinitddir@<:@=DIR@:>@],
      [sysvinit script installation directory]
    )]dnl
  )
  sysvinitddir=
  # Dispatch on "=VALUE" so that an empty argument differs from no option.
  AS_CASE(
    ["${with_sysvinitddir+=}${with_sysvinitddir}"],
    [=yes|""],
    [
      AS_IF(
        [test "x${with_sysvinitddir}" = xyes || test "x${systemdunitdir}" = x],
        [
          AS_IF(
            [test -d /etc/rc.d/init.d],
            [sysvinitddir='${sysconfdir}/rc.d/init.d'],
            [test -d /etc/init.d],
            [sysvinitddir='${sysconfdir}/init.d']
          )
        ]
      )
    ],
    [=/*],
    [sysvinitddir="${with_sysvinitddir}"],
    [=no],
    [],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR(
        [m4_normalize(
          [expected an absolute directory name for
            --with-sysvinitddir=${with_sysvinitddir}]
        )])
    ]
  )
  AS_IF(
    [test "x${sysvinitddir}" = x && test "x${with_sysvinitddir}" = xyes],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([sysvinitddir requested but not found])
    ]
  )
  AC_SUBST([sysvinitddir])
  AC_MSG_RESULT([${sysvinitddir:-disabled}])
])
