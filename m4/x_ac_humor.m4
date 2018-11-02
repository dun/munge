#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_HUMOR
#
#  DESCRIPTION:
#    Check for random silliness.
#******************************************************************************

AC_DEFUN([X_AC_HUMOR], [
  AC_CACHE_CHECK(
    [for a sense of humor],
    [x_ac_cv_humor], [
      AS_VAR_SET(x_ac_cv_humor, no)
      AS_IF([true], AS_VAR_SET(x_ac_cv_humor, yes))
    ]
  )]
)
