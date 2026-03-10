###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_LOCAL_PEERCRED
#
# DESCRIPTION:
#   Check whether the LOCAL_PEERCRED socket option is available.  Define
#   HAVE_LOCAL_PEERCRED if it is.
#
#   Compile the test rather than link it.  LOCAL_PEERCRED is a macro,
#   so its presence is settled by the preprocessor.
###############################################################################

AC_DEFUN([X_AC_CHECK_LOCAL_PEERCRED], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for LOCAL_PEERCRED sockopt],
    [x_ac_cv_check_local_peercred],
    [
      AC_COMPILE_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #include <sys/socket.h>
            #include <sys/types.h>
            #include <sys/un.h>
          ]], [[
            getsockopt (0, 0, LOCAL_PEERCRED, 0, 0);
          ]])
        ],
        [x_ac_cv_check_local_peercred=yes],
        [x_ac_cv_check_local_peercred=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_check_local_peercred}" = xyes],
    [
      AC_DEFINE(
        [HAVE_LOCAL_PEERCRED], [1],
        [Define to 1 if you have the LOCAL_PEERCRED socket option.]
      )
    ]
  )
])
