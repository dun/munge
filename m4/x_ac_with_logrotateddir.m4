###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_LOGROTATEDDIR
#
#  DESCRIPTION:
#    The "--with-logrotateddir" option sets "logrotateddir", the installation
#    directory for logrotate config files.
#
#    By default (or if this option is specified without a directory name),
#    logrotateddir will be set to "${sysconfdir}/logrotate.d" (if the
#    /etc/logrotate.d directory exists on the build system).
###############################################################################

AC_DEFUN([X_AC_WITH_LOGROTATEDDIR],
[
  AC_MSG_CHECKING([for logrotateddir])
  AC_ARG_WITH(
    [logrotateddir],
    [AS_HELP_STRING(
       [--with-logrotateddir@<:@=DIR@:>@],
       [logrotate config file installation directory])])
  AS_IF(
    [test "x${with_logrotateddir}" = xyes \
       || test "x${with_logrotateddir}" = x],
    [AS_IF(
       [test -d /etc/logrotate.d],
       [logrotateddir='${sysconfdir}/logrotate.d'])],
    [expr "x${with_logrotateddir}" : "x\/" >/dev/null 2>&1],
    [logrotateddir=${with_logrotateddir}],
    [test "x${with_logrotateddir}" != xno],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-logrotateddir=${with_logrotateddir}])])
  AS_IF(
    [test "x${logrotateddir}" = x && test "x${with_logrotateddir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([logrotateddir requested but not found])])
  AC_SUBST([logrotateddir])
  AC_MSG_RESULT([${logrotateddir:-disabled}])
])
