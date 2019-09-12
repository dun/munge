###############################################################################
#  SYNOPSIS:
#    X_AC_WITH_MUNGE_SOCKET
#
#  DESCRIPTION:
#    The "--with-munge-socket" option overrides MUNGE_SOCKET_NAME, the default
#    pathname of the MUNGE UNIX domain socket for communications between
#    client (libmunge) and server (munged).
###############################################################################

AC_DEFUN([X_AC_WITH_MUNGE_SOCKET], [
  AC_MSG_CHECKING([for MUNGE socket pathname])
  AC_ARG_WITH(
    [munge-socket],
    [AS_HELP_STRING(
       [--with-munge-socket=PATH],
       [MUNGE socket pathname default])])
 AS_IF(
   [test "x${with_munge_socket}" = xyes],
   [AC_MSG_RESULT([failed])
    AC_MSG_ERROR([missing argument to --with-munge-socket])],
   [test "x${with_munge_socket}" = xno],
   [AC_MSG_RESULT([failed])
    AC_MSG_ERROR([invalid option --without-munge-socket])],
   [expr "x${with_munge_socket}" : "x\/" >/dev/null 2>&1],
   [x_ac_with_munge_socket="${with_munge_socket}"],
   [test "x${with_munge_socket}" != x],
   [AC_MSG_RESULT([failed])
    AC_MSG_ERROR(
      [expected an absolute pathname for --with-munge-socket=${with_munge_socket}])])
  AS_IF(
    [test "x${x_ac_with_munge_socket}" != x],
    [AC_DEFINE_UNQUOTED(
       [MUNGE_SOCKET_NAME],
       ["${x_ac_with_munge_socket}"],
       [Define the MUNGE socket pathname default.])])
  AC_MSG_RESULT([${x_ac_with_munge_socket:-default}])
])
