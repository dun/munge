###############################################################################
# SYNOPSIS:
#   X_AC_DARWIN
#
# DESCRIPTION:
#   Check for Darwin platform-specific issues.
#
#   Define _DARWIN_C_SOURCE so the Darwin headers enable UNIX03 conformance.
#   Under UNIX03, <sys/cdefs.h> sets __DARWIN_UNIX03 to 1, and libpthread
#   links the cancelable variant of blocking calls such as pthread_cond_wait().
#   When __DARWIN_UNIX03 is 0, those calls are not POSIX cancellation points,
#   so pthread_cancel() cannot interrupt a thread blocked in such a call.
#
#   <sys/cdefs.h> sets __DARWIN_UNIX03 to 1 by default for a 64-bit build, and
#   for a 32-bit build that targets Mac OS X 10.5 or later.  _DARWIN_C_SOURCE
#   therefore matters only for a 32-bit build that targets an earlier release.
###############################################################################

AC_DEFUN([X_AC_DARWIN], [
  AC_REQUIRE([AC_CANONICAL_HOST])[]dnl
  case "${host}" in
    *-*-darwin*)
      AC_DEFINE(
        [_DARWIN_C_SOURCE], [1],
        [Define to 1 if you are building on Darwin.]
      )
      ;;
    *)
      ;;
  esac
])
