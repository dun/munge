#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_SELECT_AUTH_METHOD
#
#  DESCRIPTION:
#    Select the client authentication method used by MUNGE.
#
#  NOTES:
#    MUNGE supports the following methods for authenticating the UID and GID
#    of a client:
#
#    AUTH_METHOD_GETPEEREID
#     (AIX 5.2-ML4, Darwin, FreeBSD 4.6, NetBSD 5.0, OpenBSD 3.0)
#      The server uses getpeereid() to determine the identity of the client
#      connected across the Unix domain socket.
#
#    AUTH_METHOD_GETPEERUCRED
#     (SunOS 5.10)
#      The server uses getpeerucred() to determine the identity of the client
#      connected across the Unix domain socket.  The client's UID and GID are
#      then obtained via ucred_geteuid() and ucred_getegid().
#
#    AUTH_METHOD_SO_PEERCRED
#     (Linux)
#      The server uses the SO_PEERCRED socket option to determine the identity
#      of the client connected across the Unix domain socket.  The client's UID
#      and GID are then obtained from the ucred struct returned by
#      getsockopt().
#
#    AUTH_METHOD_LOCAL_PEERCRED
#     (Darwin, FreeBSD, GNU/kFreeBSD)
#      The server uses the LOCAL_PEERCRED socket option to determine the
#      identity of the client connected across the Unix domain socket.  The
#      client's UID and GID are then obtained from the xucred struct returned
#      by getsockopt().
#
#    AUTH_METHOD_RECVFD_MKFIFO
#     (Irix, SunOS)
#      The server creates a unique FIFO special file via mkfifo() and sends a
#      request to the client for it to pass an open file descriptor back across
#      this FIFO.  The client creates a unique file and sends the open
#      descriptor using the I_SENDFD ioctl(), whereby the server receives it
#      using the I_RECVFD ioctl(). The identity of the client is then obtained
#      from the strrecvfd struct used to receive the file descriptor.
#
#    AUTH_METHOD_RECVFD_MKNOD
#     (AIX)
#      The server creates a unique STREAMS-based pipe via mknod() and sends a
#      request to the client for it to pass an open file descriptor back across
#      this pipe.  The client creates a unique file and sends the open
#      descriptor using the I_SENDFD ioctl(), whereby the server receives it
#      using the I_RECVFD ioctl(). The identity of the client is then obtained
#      from the strrecvfd struct used to receive the file descriptor. The
#      server requires root privileges in order to create this pipe.
#******************************************************************************

AC_DEFUN([X_AC_SELECT_AUTH_METHOD], [
  AC_MSG_NOTICE([checking authentication support])

  AC_CHECK_FUNCS(getpeereid)
  AC_CHECK_FUNCS(getpeerucred)
  AC_CHECK_HEADERS(ucred.h)
  AC_CHECK_TYPES(struct ucred, [], [], [#include <sys/socket.h>])
  X_AC_CHECK_SO_PEERCRED
  AC_CHECK_TYPES(struct xucred, [], [], [#include <sys/param.h>
#include <sys/types.h>
#include <sys/ucred.h>])
  X_AC_CHECK_LOCAL_PEERCRED
  AC_CHECK_TYPES(struct strrecvfd, [], [], [#include <stropts.h>])
  X_AC_CHECK_FIFO_RECVFD
  AC_CHECK_FILES(/dev/spx)

  AC_MSG_CHECKING([for authentication method])
  if   test AS_VAR_GET(ac_cv_func_getpeereid) = yes ; then
    AUTH_METHOD=AUTH_METHOD_GETPEEREID
    AC_DEFINE([AUTH_METHOD_GETPEEREID], [1],
      [Define to 1 if authenticating via AUTH_METHOD_GETPEEREID]
    )
  elif test AS_VAR_GET(ac_cv_func_getpeerucred) = yes \
         -a AS_VAR_GET(ac_cv_header_ucred_h) = yes ; then
    AUTH_METHOD=AUTH_METHOD_GETPEERUCRED
    AC_DEFINE([AUTH_METHOD_GETPEERUCRED], [1],
      [Define to 1 if authenticating via AUTH_METHOD_GETPEERUCRED]
    )
  elif test AS_VAR_GET(ac_cv_type_struct_ucred) = yes \
         -a AS_VAR_GET(x_ac_cv_check_so_peercred) = yes ; then
    AUTH_METHOD=AUTH_METHOD_SO_PEERCRED
    AC_DEFINE([AUTH_METHOD_SO_PEERCRED], [1],
      [Define to 1 if authenticating via AUTH_METHOD_SO_PEERCRED]
    )
  elif test AS_VAR_GET(ac_cv_type_struct_xucred) = yes \
         -a AS_VAR_GET(x_ac_cv_check_local_peercred) = yes ; then
    AUTH_METHOD=AUTH_METHOD_LOCAL_PEERCRED
    AC_DEFINE([AUTH_METHOD_LOCAL_PEERCRED], [1],
      [Define to 1 if authenticating via AUTH_METHOD_LOCAL_PEERCRED]
    )
  elif test AS_VAR_GET(ac_cv_type_struct_strrecvfd) = yes \
         -a AS_VAR_GET(x_ac_cv_check_fifo_recvfd) = yes ; then
    AUTH_METHOD=AUTH_METHOD_RECVFD_MKFIFO
    AC_DEFINE([AUTH_METHOD_RECVFD_MKFIFO], [1],
      [Define to 1 if authenticating via AUTH_METHOD_RECVFD_MKFIFO]
    )
  elif test AS_VAR_GET(ac_cv_type_struct_strrecvfd) = yes \
         -a AS_VAR_GET(ac_cv_file__dev_spx) = yes ; then
    AUTH_METHOD=AUTH_METHOD_RECVFD_MKNOD
    AC_DEFINE([AUTH_METHOD_RECVFD_MKNOD], [1],
      [Define to 1 if authenticating via AUTH_METHOD_RECVFD_MKNOD]
    )
  else
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([cannot determine authentication method])
  fi
  AC_MSG_RESULT([$AUTH_METHOD])
])
