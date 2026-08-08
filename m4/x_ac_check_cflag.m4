###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_CFLAG(APPLY_FLAG, [TEST_FLAG = APPLY_FLAG],
#     [VARIABLE = DEBUGCFLAGS])
#
# DESCRIPTION:
#   Check whether the C compiler accepts TEST_FLAG.  If it does, append
#   APPLY_FLAG to VARIABLE.  TEST_FLAG defaults to APPLY_FLAG, and VARIABLE
#   defaults to DEBUGCFLAGS.
#
#   The test compiles a trivial source file with TEST_FLAG and "-Werror".
#   The "-Werror" is required.  GCC rejects an unrecognized "-W<name>"
#   outright.  Clang only warns about one ("-Wunknown-warning-option") and
#   still compiles.  Without "-Werror" the test would report support for
#   a flag that Clang does not implement.  Every later compile would then
#   carry the flag and emit that warning.
#
#   Only the positive form of a warning flag can be tested.  GCC accepts an
#   unrecognized "-Wno-<name>" silently.  It reports the flag only when some
#   other diagnostic fires during the compile.  So a "-Wno-<name>" flag must
#   be tested via its positive form "-W<name>": pass "-Wno-<name>" as
#   APPLY_FLAG and "-W<name>" as TEST_FLAG.  The cache result is keyed on
#   TEST_FLAG, since that is what determines whether the compiler accepts it.
#
#   The test also includes the flags already collected in VARIABLE, so that
#   a flag which depends on an earlier one is tested in the context where it
#   will be used.  Some GCC builds reject "-Wformat-security" on its own
#   with "ignored without -Wformat", which "-Werror" turns fatal; probing it
#   after "-Wall" or "-Wformat=2" reports support correctly.
#
#   The "]" and "[" around x_ac_cflag_var and x_ac_cflag_test in the test
#   body close and reopen the m4 quoting.  A macro does not expand inside a
#   quoted block, so each one is unquoted in place.
#
# INTENDED USE:
#   Probe the optional warning flags in X_AC_DEBUG, after the unconditional
#   ones are set:
#
#     DEBUGCFLAGS="${DEBUGCFLAGS} -std=c99 -pedantic -Wall"
#     X_AC_CHECK_CFLAG([-Wextra])
#     X_AC_CHECK_CFLAG([-Wformat-signedness])
#     X_AC_CHECK_CFLAG([-Wno-c11-extensions], [-Wc11-extensions])
#
#   "-Wall" must come first.  It enables "-Wformat".  "-Wformat-signedness"
#   does nothing without "-Wformat".
###############################################################################

AC_DEFUN([X_AC_CHECK_CFLAG], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  m4_pushdef([x_ac_cflag_test], [m4_default([$2], [$1])])[]dnl
  m4_pushdef([x_ac_cflag_var], [m4_default([$3], [DEBUGCFLAGS])])[]dnl
  AS_VAR_PUSHDEF([x_ac_cflag_cv], [x_ac_cv_check_cflag_]x_ac_cflag_test)[]dnl
  AC_CACHE_CHECK(
    [whether the compiler accepts ]x_ac_cflag_test,
    [x_ac_cflag_cv],
    [ x_ac_save_CFLAGS="${CFLAGS}"
      CFLAGS="${CFLAGS} ${]x_ac_cflag_var[} ]x_ac_cflag_test[ -Werror"
      AC_COMPILE_IFELSE(
        [ AC_LANG_SOURCE([[
            int x_ac_probe (void);
            int x_ac_probe (void) { return 0; }
          ]]) ],
        [AS_VAR_SET([x_ac_cflag_cv], [yes])],
        [AS_VAR_SET([x_ac_cflag_cv], [no])]
      )
      CFLAGS="${x_ac_save_CFLAGS}" ]
  )
  AS_VAR_IF(
    [x_ac_cflag_cv], [yes],
    [x_ac_cflag_var="${x_ac_cflag_var} $1"]
  )
  AS_VAR_POPDEF([x_ac_cflag_cv])[]dnl
  m4_popdef([x_ac_cflag_var])[]dnl
  m4_popdef([x_ac_cflag_test])[]dnl
])
