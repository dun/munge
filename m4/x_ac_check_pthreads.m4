###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_PTHREADS
#
# DESCRIPTION:
#   Check how to link against pthreads and set LIBPTHREAD accordingly.
#   Also define _REENTRANT and _THREAD_SAFE in config.h to enable thread-safe
#   interfaces when linking against multithreaded code.
#
#   The probe replaces LIBS rather than appending to it.  The test program
#   needs only libc and pthreads.  An unrelated library in LIBS could only
#   make the probe fail and misreport the cause.
###############################################################################

AC_DEFUN([X_AC_CHECK_PTHREADS], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [how to link against pthreads],
    [x_ac_cv_check_pthreads_flag],
    [
      x_ac_save_LIBS="${LIBS}"
      for x_ac_flag in -lpthread -pthread; do
        LIBS="${x_ac_flag}"
        AC_LINK_IFELSE(
          [
            AC_LANG_PROGRAM(
              [[#include <pthread.h>]],
              [[pthread_join (0, 0);]]
            )
          ],
          [x_ac_cv_check_pthreads_flag="${x_ac_flag}"; break],
          [x_ac_cv_check_pthreads_flag=no]
        )
      done
      LIBS="${x_ac_save_LIBS}"
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_check_pthreads_flag}" = xno],
    [AC_MSG_FAILURE([cannot link against pthreads])]
  )
  LIBPTHREAD="${x_ac_cv_check_pthreads_flag}"
  AC_SUBST([LIBPTHREAD])
  AC_DEFINE(
    [_REENTRANT], [1],
    [Define to 1 to request reentrant function definitions.]
  )
  AC_DEFINE(
    [_THREAD_SAFE], [1],
    [Define to 1 to request thread-safe function definitions.]
  )
])
