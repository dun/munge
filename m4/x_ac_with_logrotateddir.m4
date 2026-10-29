###############################################################################
# SYNOPSIS:
#   X_AC_WITH_LOGROTATEDDIR
#
# DESCRIPTION:
#   The "--with-logrotateddir" option sets "logrotateddir", the installation
#   directory for logrotate config files.
#
#   This option requires an absolute directory name for its argument.
#
#   By default (or if this option is specified without a directory name),
#   logrotateddir will be set to "${sysconfdir}/logrotate.d" (if the
#   /etc/logrotate.d directory exists on the build system).  A bare
#   "--with-logrotateddir" fails if that directory does not exist.
#
#   Specifying "--without-logrotateddir" disables it.
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_LOGROTATEDDIR], [
  AC_MSG_CHECKING([for logrotateddir])
  AC_ARG_WITH(
    [logrotateddir],
    [AS_HELP_STRING(
      [--with-logrotateddir@<:@=DIR@:>@],
      [logrotate config file installation directory]
    )]dnl
  )
  logrotateddir=
  # Dispatch on "=VALUE" so that an empty argument differs from no option.
  AS_CASE(
    ["${with_logrotateddir+=}${with_logrotateddir}"],
    [=yes|""],
    [
      AS_IF(
        [test -d /etc/logrotate.d],
        [logrotateddir='${sysconfdir}/logrotate.d']
      )
    ],
    [=/*],
    [logrotateddir="${with_logrotateddir}"],
    [=no],
    [],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR(
        [m4_normalize(
          [expected an absolute directory name for
            --with-logrotateddir=${with_logrotateddir}]
        )])
    ]
  )
  AS_IF(
    [test "x${logrotateddir}" = x && test "x${with_logrotateddir}" = xyes],
    [
      AC_MSG_RESULT([failed])
      AC_MSG_ERROR([logrotateddir requested but not found])
    ]
  )
  AC_SUBST([logrotateddir])
  AC_MSG_RESULT([${logrotateddir:-disabled}])
])
