###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_MEMSET_S
#
# DESCRIPTION:
#   Check for memset_s() (C11 Annex K), which requires opting in via
#   "__STDC_WANT_LIB_EXT1__" before including <string.h>.  Standard
#   AC_CHECK_FUNCS cannot handle this opt-in, so use AC_LINK_IFELSE.
#   If found, define HAVE_MEMSET_S and NEED_STDC_WANT_LIB_EXT1.
#
#   Set the defines outside the cached probe.  A cached run skips the
#   probe body, so a define made inside it would be lost.
###############################################################################

AC_DEFUN([X_AC_CHECK_MEMSET_S], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for memset_s with __STDC_WANT_LIB_EXT1__],
    [x_ac_cv_check_memset_s],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #define __STDC_WANT_LIB_EXT1__ 1
            #include <string.h>
          ]], [[
            char buf[8];
            (void) memset_s (buf, sizeof buf, 0, sizeof buf);
          ]])
        ],
        [x_ac_cv_check_memset_s=yes],
        [x_ac_cv_check_memset_s=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_check_memset_s}" = xyes],
    [
      AC_DEFINE(
        [HAVE_MEMSET_S], [1],
        [Define to 1 if you have the 'memset_s' function.]
      )
      AC_DEFINE(
        [NEED_STDC_WANT_LIB_EXT1], [1],
        [Define to 1 before including <string.h> to expose 'memset_s'.]
      )
    ]
  )
])
