###############################################################################
# SYNOPSIS:
#   X_AC_SELECT_AUTH_METHOD
#
# DESCRIPTION:
#   Select the client authentication method used by MUNGE.
#
# NOTES:
#   Authenticate the UID and GID of a client with one of the following methods.
#
#   AUTH_METHOD_GETPEEREID
#    (AIX 5.2-ML4, Darwin, FreeBSD 4.6, NetBSD 5.0, OpenBSD 3.0)
#     The server calls getpeereid() on the UNIX domain socket.  That call
#     returns the client's UID and GID.
#
#   AUTH_METHOD_GETPEERUCRED
#    (SunOS 5.10)
#     The server calls getpeerucred() on the UNIX domain socket.  That call
#     returns a ucred_t for the client.  ucred_geteuid() and ucred_getegid()
#     then read the UID and GID from the ucred_t.
#
#   AUTH_METHOD_SO_PEERCRED
#    (Linux)
#     The server calls getsockopt() with the SO_PEERCRED socket option on
#     the UNIX domain socket.  That option returns a ucred struct holding
#     the client's UID and GID.
#
#   AUTH_METHOD_LOCAL_PEERCRED
#    (Darwin, FreeBSD, GNU/kFreeBSD)
#     The server calls getsockopt() with the LOCAL_PEERCRED socket option on
#     the UNIX domain socket.  That option returns an xucred struct holding
#     the client's UID and GID.
#
#   AUTH_METHOD_RECVFD_MKFIFO
#    (Irix, SunOS)
#     The server creates a unique FIFO with mkfifo().  It then requests an
#     open file descriptor from the client.  The client creates a unique file
#     and sends the descriptor across that FIFO with the I_SENDFD ioctl().
#     The server receives it with the I_RECVFD ioctl().  The receiving
#     ioctl() fills in a strrecvfd struct holding the client's UID and GID.
#
#   AUTH_METHOD_RECVFD_MKNOD
#    (AIX)
#     The server creates a unique STREAMS-based pipe with mknod().  It then
#     requests an open file descriptor from the client.  The client creates
#     a unique file and sends the descriptor across that pipe with the
#     I_SENDFD ioctl().  The server receives it with the I_RECVFD ioctl().
#     The receiving ioctl() fills in a strrecvfd struct holding the client's
#     UID and GID.  The server needs root privileges to create the pipe.
###############################################################################

AC_DEFUN([X_AC_SELECT_AUTH_METHOD], [
  AC_MSG_NOTICE([checking authentication support])
  AC_CHECK_FUNCS([getpeereid])
  AC_CHECK_FUNCS([getpeerucred])
  AC_CHECK_HEADERS([ucred.h])
  AC_CHECK_TYPES([struct ucred], [], [], [#include <sys/socket.h>])
  X_AC_CHECK_SO_PEERCRED
  AC_CHECK_TYPES(
    [struct xucred], [], [],
    [
      #include <sys/param.h>
      #include <sys/types.h>
      #include <sys/ucred.h>
    ]
  )
  X_AC_CHECK_LOCAL_PEERCRED
  AC_CHECK_TYPES([struct strrecvfd], [], [], [#include <stropts.h>])
  X_AC_CHECK_FIFO_RECVFD
  AC_CACHE_CHECK(
    [for /dev/spx],
    [ac_cv_file__dev_spx],
    [
      if test "x${cross_compiling}" = xyes; then
        case "${host_os}" in
          aix*)
            ac_cv_file__dev_spx=yes ;;
          *)
            ac_cv_file__dev_spx=unlikely ;;
        esac
      else
        if test -e "/dev/spx"; then
          ac_cv_file__dev_spx=yes
        else
          ac_cv_file__dev_spx=no
        fi
      fi
    ]
  )
  AC_MSG_CHECKING([for authentication method])
  if test "x${ac_cv_func_getpeereid}" = xyes; then
    AUTH_METHOD=AUTH_METHOD_GETPEEREID
    AC_DEFINE(
      [AUTH_METHOD_GETPEEREID], [1],
      [Define to 1 if authenticating via AUTH_METHOD_GETPEEREID.]
    )
  elif test "x${ac_cv_func_getpeerucred}" = xyes \
      && test "x${ac_cv_header_ucred_h}" = xyes; then
    AUTH_METHOD=AUTH_METHOD_GETPEERUCRED
    AC_DEFINE(
      [AUTH_METHOD_GETPEERUCRED], [1],
      [Define to 1 if authenticating via AUTH_METHOD_GETPEERUCRED.]
    )
  elif test "x${ac_cv_type_struct_ucred}" = xyes \
      && test "x${x_ac_cv_check_so_peercred}" = xyes; then
    AUTH_METHOD=AUTH_METHOD_SO_PEERCRED
    AC_DEFINE(
      [AUTH_METHOD_SO_PEERCRED], [1],
      [Define to 1 if authenticating via AUTH_METHOD_SO_PEERCRED.]
    )
  elif test "x${ac_cv_type_struct_xucred}" = xyes \
      && test "x${x_ac_cv_check_local_peercred}" = xyes; then
    AUTH_METHOD=AUTH_METHOD_LOCAL_PEERCRED
    AC_DEFINE(
      [AUTH_METHOD_LOCAL_PEERCRED], [1],
      [Define to 1 if authenticating via AUTH_METHOD_LOCAL_PEERCRED.]
    )
  elif test "x${ac_cv_type_struct_strrecvfd}" = xyes \
      && test "x${x_ac_cv_check_fifo_recvfd}" = xyes; then
    AUTH_METHOD=AUTH_METHOD_RECVFD_MKFIFO
    AC_DEFINE(
      [AUTH_METHOD_RECVFD_MKFIFO], [1],
      [Define to 1 if authenticating via AUTH_METHOD_RECVFD_MKFIFO.]
    )
  elif test "x${ac_cv_type_struct_strrecvfd}" = xyes \
      && test "x${ac_cv_file__dev_spx}" = xyes; then
    AUTH_METHOD=AUTH_METHOD_RECVFD_MKNOD
    AC_DEFINE(
      [AUTH_METHOD_RECVFD_MKNOD], [1],
      [Define to 1 if authenticating via AUTH_METHOD_RECVFD_MKNOD.]
    )
  else
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([cannot determine authentication method])
  fi
  AC_MSG_RESULT([${AUTH_METHOD}])
])
