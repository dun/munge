###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_SO_PEERCRED
#
# DESCRIPTION:
#   Check whether the SO_PEERCRED socket option is available.  Define
#   HAVE_SO_PEERCRED if it is.
#
#   Compile the test rather than link it.  SO_PEERCRED is a macro, so its
#   presence is settled by the preprocessor.
###############################################################################

AC_DEFUN([X_AC_CHECK_SO_PEERCRED], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for SO_PEERCRED sockopt],
    [x_ac_cv_check_so_peercred],
    [
      AC_COMPILE_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #include <sys/socket.h>
            #include <sys/types.h>
          ]], [[
            getsockopt (0, SOL_SOCKET, SO_PEERCRED, 0, 0);
          ]])
        ],
        [x_ac_cv_check_so_peercred=yes],
        [x_ac_cv_check_so_peercred=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_check_so_peercred}" = xyes],
    [
      AC_DEFINE(
        [HAVE_SO_PEERCRED], [1],
        [Define to 1 if you have the SO_PEERCRED socket option.]
      )
    ]
  )
])
