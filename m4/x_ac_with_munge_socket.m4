******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_WITH_MUNGE_SOCKET
#
#  DESCRIPTION:
#    The "--with-munge-socket=PATH" configure script option overrides
#    MUNGE_SOCKET_NAME, the default location of the local domain socket for
#    communications between MUNGE client and server.
#******************************************************************************

AC_DEFUN([X_AC_WITH_MUNGE_SOCKET], [
  AC_MSG_CHECKING([for MUNGE socket pathname])
  AC_ARG_WITH(
    [munge-socket],
    [AS_HELP_STRING(
      [--with-munge-socket=PATH],
      [specify default MUNGE socket pathname])],
    [if expr X"${withval}" : "X\/" >/dev/null 2>&1; then
       x_ac_with_munge_socket="${withval}";
     else
       AC_MSG_RESULT([failed])
       AC_MSG_ERROR([bad value for --with-munge-socket])
     fi])
  AS_IF(
    [test -n "${x_ac_with_munge_socket}"],
    [AC_DEFINE_UNQUOTED(
      [MUNGE_SOCKET_NAME],
      ["${x_ac_with_munge_socket}"],
      [Define the default MUNGE socket pathname.])])
  AC_MSG_RESULT([${x_ac_with_munge_socket:-default}])
])
