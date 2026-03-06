###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_MEMSET_S
#
# DESCRIPTION:
#   Check for memset_s() (C11 Annex K), which requires opting in via
#   "__STDC_WANT_LIB_EXT1__" before including <string.h>.  Standard
#   AC_CHECK_FUNCS cannot handle this opt-in, so use AC_LINK_IFELSE.
#   If found, define HAVE_MEMSET_S and NEED_STDC_WANT_LIB_EXT1.
###############################################################################

AC_DEFUN([X_AC_CHECK_MEMSET_S], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_MSG_CHECKING([for memset_s with __STDC_WANT_LIB_EXT1__])
  AC_LINK_IFELSE(
    [
      AC_LANG_PROGRAM([[
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
]], [[
char buf[8]; (void) memset_s (buf, sizeof buf, 0, sizeof buf);
]]
      )
    ], [
      AC_DEFINE([HAVE_MEMSET_S], [1],
        [Define to 1 if you have the 'memset_s' function.]
      )
      AC_DEFINE([NEED_STDC_WANT_LIB_EXT1], [1],
        [Define to 1 before including <string.h> to expose 'memset_s'.]
      )
      AC_MSG_RESULT([yes])
    ],
    [AC_MSG_RESULT([no])]
  )]
)
