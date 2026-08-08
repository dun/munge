###############################################################################
# SYNOPSIS:
#   X_AC_DEBUG
#
# DESCRIPTION:
#   Add support for the "--enable-debug" configure option.  If enabled,
#   collect debugging flags in DEBUGCFLAGS and append them to AM_CFLAGS.
#   Otherwise define NDEBUG to disable assert() checks.
#
#   Probe the optional warning flags with X_AC_CHECK_CFLAG.  The set
#   depends on what the compiler accepts.
###############################################################################

AC_DEFUN([X_AC_DEBUG], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_MSG_CHECKING([whether debugging is enabled])
  AC_ARG_ENABLE(
    [debug],
    AS_HELP_STRING([--enable-debug], [enable debugging for code development]),
    [ case "${enableval}" in
        yes|no)
          x_ac_debug="${enableval}" ;;
        *)
          AC_MSG_RESULT([failed])
          AC_MSG_ERROR([bad value "${enableval}" for --enable-debug]) ;;
      esac ]
  )
  AC_MSG_RESULT([${x_ac_debug=no}])
  AS_IF(
    [test "x${x_ac_debug}" = xyes],
    [ # Clear configure's default CFLAGS when not explicitly set by user.
      AS_IF(
        [test "x${ac_env_CFLAGS_set}" = x],
        [CFLAGS=]
      )
      DEBUGCFLAGS="${DEBUGCFLAGS} -O0"
      AS_IF(
        [test "x${ac_cv_prog_cc_g}" = xyes],
        [DEBUGCFLAGS="${DEBUGCFLAGS} -g"]
      )
      AS_IF(
        [test "x${GCC}" = xyes],
        [ DEBUGCFLAGS="${DEBUGCFLAGS} -std=c99 -pedantic -Wall"
          X_AC_CHECK_CFLAG([-Wextra])
          X_AC_CHECK_CFLAG([-Wformat=2])
          # "-Wformat=2" already implies "-Wformat-security".  Probe it
          # explicitly so the check survives removal of "-Wformat=2".
          # Clang enables it by default, so the probe is a no-op there.
          X_AC_CHECK_CFLAG([-Wformat-security])
          X_AC_CHECK_CFLAG([-Wformat-signedness])
          # glibc 2.43 defines strchr(), strrchr(), and similar
          # functions as C23 type-generic macros built with "_Generic".
          # Under "-std=c99 -pedantic", Clang flags each expansion as a
          # C11 extension.  Probe the positive "-Wc11-extensions" form.
          # GCC accepts an unknown "-Wno-" flag silently.
          X_AC_CHECK_CFLAG([-Wno-c11-extensions], [-Wc11-extensions])
          _X_AC_DEBUG_FORMAT_NONLITERAL ]
      )
      AM_CFLAGS="${AM_CFLAGS} \$(DEBUGCFLAGS)"
      AC_SUBST([AM_CFLAGS])
      AC_SUBST([DEBUGCFLAGS]) ],
    [ # Debugging not enabled.
      AC_DEFINE(
        [NDEBUG], [1],
        [Define to 1 if you are building a production release.]
      ) ]
  ) ]
)

###############################################################################
# SYNOPSIS:
#   _X_AC_DEBUG_FORMAT_NONLITERAL
#
# DESCRIPTION:
#   Disable "-Wformat-nonliteral" when the compiler cannot suppress it at the
#   call site.  "-Wformat=2" enables that warning.  The tree suppresses it
#   with the DIAG_OFF() macro from "diag.h", which expands to an in-function
#   diagnostic pragma.  GCC honors that pragma only in v4.6 or later.
#
#   Probe the pragma in the assembled DEBUGCFLAGS context with "-Werror" so
#   the test matches the real build.  A compiler that ignores the pragma
#   warns; one that rejects it errors.  Either way the probe fails, and
#   "-Wno-format-nonliteral" then disables the warning for the whole build.
#   This is a feature test rather than a version check.
#
#   The probe takes "struct tm" as a parameter rather than declaring an
#   uninitialized local.  A local would trip "-Wuninitialized" under
#   "-Wextra" and fail the test on a capable compiler.
###############################################################################

AC_DEFUN([_X_AC_DEBUG_FORMAT_NONLITERAL], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [whether in-function pragmas suppress -Wformat-nonliteral],
    [x_ac_cv_debug_format_nonliteral],
    [ x_ac_save_CFLAGS="${CFLAGS}"
      CFLAGS="${CFLAGS} ${DEBUGCFLAGS} -Wformat-nonliteral -Werror"
      AC_COMPILE_IFELSE(
        [ AC_LANG_SOURCE([[
            #include <time.h>
            size_t x_ac_probe (char *s, size_t n, const char *f, struct tm *t);
            size_t x_ac_probe (char *s, size_t n, const char *f, struct tm *t)
            {
                size_t r;
                _Pragma ("GCC diagnostic push")
                _Pragma ("GCC diagnostic ignored \"-Wformat-nonliteral\"")
                r = strftime (s, n, f, t);
                _Pragma ("GCC diagnostic pop")
                return r;
            }
          ]]) ],
        [x_ac_cv_debug_format_nonliteral=yes],
        [x_ac_cv_debug_format_nonliteral=no]
      )
      CFLAGS="${x_ac_save_CFLAGS}" ]
  )
  AS_IF(
    [test "x${x_ac_cv_debug_format_nonliteral}" = xno],
    [X_AC_CHECK_CFLAG([-Wno-format-nonliteral], [-Wformat-nonliteral])]
  ) ]
)
