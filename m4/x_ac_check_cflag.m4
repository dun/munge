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
#   The test compiles a trivial source file with TEST_FLAG and "-Werror",
#   and fails on any compiler output.  AC_COMPILE_IFELSE tests only the
#   exit status unless "ac_c_werror_flag" is set; with it set, a non-empty
#   stderr also fails the probe.  GCC rejects an unrecognized "-W<name>"
#   outright.  Clang reports "-Wunknown-warning-option" and still compiles,
#   and Clang 1.1 exits 0 even under "-Werror".  An exit-status test there
#   reports support for a flag the compiler does not implement, and every
#   later compile carries the flag and emits that warning.  The stderr test
#   catches the diagnostic either way.
#
#   Only the positive form of a warning flag can be tested.  GCC accepts
#   an unrecognized "-Wno-<name>" silently.  It reports the flag only when
#   it emits some other diagnostic during the compile.  So a "-Wno-<name>"
#   flag must be tested via its positive form "-W<name>": pass "-Wno-<name>"
#   as APPLY_FLAG and "-W<name>" as TEST_FLAG.  The cache result is keyed
#   on TEST_FLAG, the flag the probe compiles.
#
#   The test also includes the flags already collected in VARIABLE, so
#   that a flag which depends on an earlier one is tested in the context
#   where it will be used.  GCC warns that "-Wformat-security" is ignored
#   without "-Wformat", so probing "-Wformat-security" alone reports "no".
#   Probing it after "-Wall" or "-Wformat=2" reports support correctly.
#
#   Wrap each argument in m4_normalize.  The arguments reach the generated
#   shell verbatim, so a call spanning lines would otherwise carry its
#   newlines and indentation into "${VARIABLE}".
#
# USAGE:
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
  m4_pushdef([x_ac_cflag_apply], [m4_normalize([$1])])[]dnl
  m4_pushdef([x_ac_cflag_test], [m4_normalize(m4_default([$2], [$1]))])[]dnl
  m4_pushdef([x_ac_cflag_var], [m4_normalize(m4_default([$3], [DEBUGCFLAGS]))])[]dnl
  AS_VAR_PUSHDEF([x_ac_cflag_cv], [x_ac_cv_check_cflag_]x_ac_cflag_test)[]dnl
  AC_CACHE_CHECK(
    [whether the compiler accepts x_ac_cflag_test],
    [x_ac_cflag_cv],
    [
      x_ac_cflag_save_CFLAGS="${CFLAGS}"
      x_ac_cflag_save_werror="${ac_c_werror_flag}"
      CFLAGS="${CFLAGS} ${x_ac_cflag_var} x_ac_cflag_test -Werror"
      ac_c_werror_flag=yes
      AC_COMPILE_IFELSE(
        [
          AC_LANG_SOURCE([[
            int x_ac_probe (void);
            int x_ac_probe (void) { return 0; }
          ]])
        ],
        [AS_VAR_SET([x_ac_cflag_cv], [yes])],
        [AS_VAR_SET([x_ac_cflag_cv], [no])]
      )
      CFLAGS="${x_ac_cflag_save_CFLAGS}"
      ac_c_werror_flag="${x_ac_cflag_save_werror}"
    ]
  )
  AS_VAR_IF(
    [x_ac_cflag_cv], [yes],
    [x_ac_cflag_var="${x_ac_cflag_var} x_ac_cflag_apply"]
  )
  AS_VAR_POPDEF([x_ac_cflag_cv])[]dnl
  m4_popdef([x_ac_cflag_var])[]dnl
  m4_popdef([x_ac_cflag_test])[]dnl
  m4_popdef([x_ac_cflag_apply])[]dnl
])
