###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_FIFO_RECVFD
#
# DESCRIPTION:
#   Check whether a fifo made by mkfifo() can pass a file descriptor through
#   the I_RECVFD ioctl into a struct strrecvfd.  Define HAVE_FIFO_RECVFD
#   if it can.
#
#   Run the test rather than link it.  A system can declare I_RECVFD and
#   still reject the ioctl on a fifo, so only running the program answers
#   the question.  Report no when cross compiling, since the test cannot run.
###############################################################################

AC_DEFUN([X_AC_CHECK_FIFO_RECVFD], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [if file descriptors can be passed over a fifo],
    [x_ac_cv_check_fifo_recvfd],
    [
      x_ac_cv_check_fifo_recvfd=no
      AC_RUN_IFELSE(
        [
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
          ]], [[
            char name[PATH_MAX];
            char *tmpdir;
            char *prefix = "fifo";
            int fd;
            struct strrecvfd recvfd;
            int rv = 1;

            if (!(tmpdir = getenv ("TMPDIR"))) {
                tmpdir = "/tmp";
            }
            snprintf (name, sizeof name, "%s/.%s.%d",
                    tmpdir, prefix, getpid ());
            unlink (name);
            if (   (mkfifo (name, S_IWUSR | S_IRUSR) == 0)
                && ((fd = open (name, O_RDONLY | O_NONBLOCK)) >= 0)
                && ((ioctl (fd, I_RECVFD, &recvfd) == -1)
                    && (errno == EAGAIN))) {
                rv = 0;
            }
            unlink (name);
            return rv;
          ]])
        ],
        [x_ac_cv_check_fifo_recvfd=yes],
        [x_ac_cv_check_fifo_recvfd=no],
        [x_ac_cv_check_fifo_recvfd=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_check_fifo_recvfd}" = xyes],
    [
      AC_DEFINE(
        [HAVE_FIFO_RECVFD], [1],
        [Define to 1 if file descriptors can be passed over a fifo.]
      )
    ]
  )
])
