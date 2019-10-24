###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_PKGCONFIGDIR
#
#  DESCRIPTION:
#    The "--with-pkgconfigdir" option sets "pkgconfigdir", the installation
#    directory for pkg-config .pc files.
#
#    By default (or if this option is specified without a directory name),
#    pkgconfigdir will be set to "${libdir}/pkgconfig" (if some
#    /usr/lib*/pkgconfig directory exists on the build system).
###############################################################################

AC_DEFUN([X_AC_WITH_PKGCONFIGDIR],
[
  AC_MSG_CHECKING([for pkgconfigdir])
  AC_ARG_WITH(
    [pkgconfigdir],
    [AS_HELP_STRING(
       [--with-pkgconfigdir@<:@=DIR@:>@],
       [pkg-config .pc file installation directory])])
  AS_IF(
    [test "x${with_pkgconfigdir}" = xyes \
       || test "x${with_pkgconfigdir}" = x],
    [AS_IF(
       [find /usr/lib*/pkgconfig -type d >/dev/null 2>&1],
       [pkgconfigdir='${libdir}/pkgconfig'])],
    [expr "x${with_pkgconfigdir}" : "x\/" >/dev/null 2>&1],
    [pkgconfigdir=${with_pkgconfigdir}],
    [test "x${with_pkgconfigdir}" != xno],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR(
       [expected an absolute directory name for --with-pkgconfigdir=${with_pkgconfigdir}])])
  AS_IF(
    [test "x${pkgconfigdir}" = x && test "x${with_pkgconfigdir}" = xyes],
    [AC_MSG_RESULT([failed])
     AC_MSG_ERROR([pkgconfigdir requested but not found])])
  AC_SUBST([pkgconfigdir])
  AC_MSG_RESULT([${pkgconfigdir:-disabled}])
])
