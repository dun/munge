###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_LD_NO_UNDEFINED
#
# DESCRIPTION:
#   Check whether the linker supports the "-Wl,--no-undefined" flag,
#   which causes the linker to fail at shared-library link time if the
#   library contains unresolved external references that are not provided
#   by libraries on the link line.  GNU ld supports this.
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
    [whether the linker supports --no-undefined],
    [x_ac_cv_check_ld_no_undefined],
    [x_ac_save_LDFLAGS="${LDFLAGS}"
     LDFLAGS="${LDFLAGS} -Wl,--no-undefined"
     AC_LINK_IFELSE(
       [AC_LANG_PROGRAM([], [])],
       [x_ac_cv_check_ld_no_undefined=yes],
       [x_ac_cv_check_ld_no_undefined=no]
     )
     LDFLAGS="${x_ac_save_LDFLAGS}"]
  )
  AS_IF(
    [test "x${x_ac_cv_check_ld_no_undefined}" = xyes],
    [LD_NO_UNDEFINED="-Wl,--no-undefined"],
    [LD_NO_UNDEFINED=""]
  )
  AC_SUBST([LD_NO_UNDEFINED])]
)
