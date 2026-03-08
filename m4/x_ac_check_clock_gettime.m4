###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_CLOCK_GETTIME
#
# DESCRIPTION:
#   Check for clock_gettime() with librt if needed.
###############################################################################

AC_DEFUN([X_AC_CHECK_CLOCK_GETTIME], [
  X_AC_CHECK_COND_LIB([rt], [clock_gettime])
  x_ac_check_clock_gettime_save_LIBS="${LIBS}"
  AS_IF([test "x${ac_cv_lib_rt_clock_gettime}" = xyes], [LIBS="${LIBS} -lrt"])
  AC_CHECK_FUNCS([clock_gettime])
  LIBS="${x_ac_check_clock_gettime_save_LIBS}"
  unset x_ac_check_clock_gettime_save_LIBS]
)
