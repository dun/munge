###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_LD_NO_UNDEFINED
#
# DESCRIPTION:
#   Check whether the linker supports the "-Wl,--no-undefined" flag in
#   a shared-library link context.  When set, this flag causes the linker
#   to fail at shared-library link time if the library contains unresolved
#   external references that are not provided by libraries on the link line.
#   GNU ld supports this; some other linkers do not (e.g., macOS ld rejects
#   the flag).  On some platforms (e.g., OpenBSD), the shared-library
#   link line does not automatically include libc, so the flag's strict
#   resolution requirement cannot be satisfied even when the linker itself
#   accepts the flag.
#
#   The test compiles a small source file (with "-fPIC", which libtool
#   adds automatically when building libmunge.la) that references
#   a libc symbol and attempts to link it as a shared object (with
#   "-shared" and "-Wl,--no-undefined").  This mirrors the actual usage in
#   libmunge_la_LDFLAGS more closely than a plain link test.  The libc symbol
#   must be called with a runtime-valued argument because the compiler can
#   fold calls like strlen("") to a constant at compile time regardless
#   of optimization level, eliminating the libc reference and causing the
#   test to incorrectly report support on platforms (e.g., OpenBSD) where
#   the actual libmunge.la shared-library link fails.
#
#   Intended use: add $(LD_NO_UNDEFINED) to *_LDFLAGS for any libtool shared
#   library that should be self-contained:
#
#     libmunge_la_LDFLAGS = \
#         -no-undefined $(LD_NO_UNDEFINED) ...
#
#   The libtool "-no-undefined" flag is a declaration of intent and is needed
#   for libtool to allow shared-library creation on platforms that require
#   all symbols to be resolved.  It does not enforce the check on GNU ld,
#   where "-Wl,--no-undefined" is needed instead.
###############################################################################

AC_DEFUN([X_AC_CHECK_LD_NO_UNDEFINED], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [whether the linker supports --no-undefined for shared libraries],
    [x_ac_cv_check_ld_no_undefined],
    [x_ac_save_CFLAGS="${CFLAGS}"
     x_ac_save_LDFLAGS="${LDFLAGS}"
     CFLAGS="${CFLAGS} -fPIC"
     LDFLAGS="${LDFLAGS} -shared -Wl,--no-undefined"
     AC_LINK_IFELSE(
       [AC_LANG_SOURCE([[
         #include <stddef.h>
         #include <string.h>
         size_t f(const char *s) { return strlen(s); }
       ]])],
       [x_ac_cv_check_ld_no_undefined=yes],
       [x_ac_cv_check_ld_no_undefined=no]
     )
     CFLAGS="${x_ac_save_CFLAGS}"
     LDFLAGS="${x_ac_save_LDFLAGS}"]
  )
  AS_IF(
    [test "x${x_ac_cv_check_ld_no_undefined}" = xyes],
    [LD_NO_UNDEFINED="-Wl,--no-undefined"],
    [LD_NO_UNDEFINED=""]
  )
  AC_SUBST([LD_NO_UNDEFINED])]
)
