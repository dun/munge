#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CHECK_FIFO_RECVFD
#
#  DESCRIPTION:
#    Check to see if a fifo (constructed via mkfifo) can be used to pass
#    file descriptors using a struct strrecvfd and the I_RECVFD ioctl.
#******************************************************************************

AC_DEFUN([X_AC_CHECK_FIFO_RECVFD], [
  AC_CACHE_CHECK(
    [if file descriptors can be passed over a fifo],
    [x_ac_cv_check_fifo_recvfd], [
    AS_VAR_SET(x_ac_cv_check_fifo_recvfd, no)
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif /* !PATH_MAX */
]],
[[
char name[PATH_MAX];
char *tmpdir;
char *basename = "fifo";
int fd;
struct strrecvfd recvfd;
int rc = 1;

if (!(tmpdir = getenv ("TMPDIR")))
    tmpdir = "/tmp";
snprintf (name, sizeof (name), "%s/.%s.%d", tmpdir, basename, getpid ());
unlink (name);
if ( ( mkfifo (name, S_IWUSR | S_IRUSR) == 0)
  && ((fd = open (name, O_RDONLY | O_NONBLOCK)) >= 0)
  && ((ioctl (fd, I_RECVFD, &recvfd) == -1) && (errno == EAGAIN)) ) {
    rc = 0;
}
unlink (name);
return (rc); ]]
      )],
      AS_VAR_SET(x_ac_cv_check_fifo_recvfd, yes),
      AS_VAR_SET(x_ac_cv_check_fifo_recvfd, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_check_fifo_recvfd) = yes],
    AC_DEFINE([HAVE_FIFO_RECVFD], [1],
      [Define to 1 if file descriptors can be passed over a fifo.]
    )
  )]
)
