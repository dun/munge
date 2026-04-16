###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_CLOCK_GETTIME
#
# DESCRIPTION:
#   Check for clock_gettime(), linking against librt if needed.
#   If clock_gettime() is available, also probe for optional clockid_t
#   constants CLOCK_MONOTONIC and CLOCK_PROCESS_CPUTIME_ID.
###############################################################################

AC_DEFUN([X_AC_CHECK_CLOCK_GETTIME], [
  X_AC_CHECK_COND_LIB([rt], [clock_gettime])
  x_ac_check_clock_gettime_save_LIBS="${LIBS}"
  AS_IF([test "x${ac_cv_lib_rt_clock_gettime}" = xyes], [LIBS="${LIBS} -lrt"])
  AC_CHECK_FUNCS([clock_gettime])
  AS_IF([test "x${ac_cv_func_clock_gettime}" = xyes], [
    AC_CHECK_DECLS(
      [CLOCK_MONOTONIC,
       CLOCK_PROCESS_CPUTIME_ID],
      [],
      [],
      [[#include <time.h>]]
    )]
  )
  LIBS="${x_ac_check_clock_gettime_save_LIBS}"
  unset x_ac_check_clock_gettime_save_LIBS]
)
