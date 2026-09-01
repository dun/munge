###############################################################################
# SYNOPSIS:
#   X_AC_GETGRENT
#
# DESCRIPTION:
#   Check what forms of getgrent() and getgrent_r() are supported.
#
#   Compile the probes with "ac_c_werror_flag=yes", which fails a probe on
#   any compiler diagnostic.  The AIX and GNU getgrent_r() prototypes take
#   a different pointer type for the fourth parameter.  Clang reports that
#   mismatch as a warning, so without the flag both probes would succeed on a
#   platform providing either form.  GCC 14 reports it as an error by default.
#
#   Add "-Wno-implicit-function-declaration" to the probes.  A platform
#   without getgrent_r() declares nothing, and the diagnostic would fail
#   the probe at compile time.  The flag lets the link decide instead.
#
#   Use AC_LINK_IFELSE for the getgrent_r() probes rather than
#   AC_COMPILE_IFELSE.  A platform with no getgrent_r() still compiles them.
#   The missing function is only detected at link time.
###############################################################################

AC_DEFUN([X_AC_GETGRENT], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CHECK_FUNCS([getgrent])
  _X_AC_GETGRENT_CHECK_WNO_IMPLICIT
  x_ac_save_CFLAGS="${CFLAGS}"
  x_ac_save_werror="${ac_c_werror_flag}"
  CFLAGS="${CFLAGS} ${x_ac_getgrent_wno_implicit_flag}"
  ac_c_werror_flag=yes
  _X_AC_GETGRENT_R_AIX
  _X_AC_GETGRENT_R_GNU
  _X_AC_GETGRENT_R_SUN
  CFLAGS="${x_ac_save_CFLAGS}"
  ac_c_werror_flag="${x_ac_save_werror}"
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETGRENT_CHECK_WNO_IMPLICIT
#
# DESCRIPTION:
#   Check if the compiler supports the -Wno-implicit-function-declaration flag.
###############################################################################

AC_DEFUN([_X_AC_GETGRENT_CHECK_WNO_IMPLICIT], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_MSG_CHECKING([if ${CC} supports -Wno-implicit-function-declaration])
  x_ac_save_CFLAGS="${CFLAGS}"
  CFLAGS="${CFLAGS} -Wno-implicit-function-declaration -Werror"
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM()],
    [
      x_ac_getgrent_have_wno_implicit=yes
      x_ac_getgrent_wno_implicit_flag="-Wno-implicit-function-declaration"
    ], [
      x_ac_getgrent_have_wno_implicit=no
      x_ac_getgrent_wno_implicit_flag=""
    ]
  )
  CFLAGS="${x_ac_save_CFLAGS}"
  AS_IF(
    [test "x${x_ac_getgrent_have_wno_implicit}" = xyes],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])]
  )
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETGRENT_R_AIX
#
# DESCRIPTION:
#   Check for the AIX form of getgrent_r(), which takes a FILE ** for its
#   last parameter.
###############################################################################

AC_DEFUN([_X_AC_GETGRENT_R_AIX], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getgrent_r (AIX)],
    [x_ac_cv_have_getgrent_r_aix],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #define _THREAD_SAFE 1
            #include <grp.h>
            #include <stdio.h>
          ]], [[
            int rv;
            struct group gr;
            char buf[1024];
            FILE *fp;
            rv = getgrent_r (&gr, buf, sizeof buf, &fp); (void) rv;
          ]])
        ],
        [x_ac_cv_have_getgrent_r_aix=yes],
        [x_ac_cv_have_getgrent_r_aix=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getgrent_r_aix}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETGRENT_R_AIX], [1],
        [Define to 1 if you have the 'getgrent_r' function from AIX.]
      )
    ]
  )
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETGRENT_R_GNU
#
# DESCRIPTION:
#   Check for the GNU form of getgrent_r(), which takes a struct group **
#   for its last parameter.
###############################################################################

AC_DEFUN([_X_AC_GETGRENT_R_GNU], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getgrent_r (GNU)],
    [x_ac_cv_have_getgrent_r_gnu],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #define _GNU_SOURCE 1
            #include <grp.h>
          ]], [[
            int rv;
            struct group gr, *pgr;
            char buf[1024];
            rv = getgrent_r (&gr, buf, sizeof buf, &pgr); (void) rv;
          ]])
        ],
        [x_ac_cv_have_getgrent_r_gnu=yes],
        [x_ac_cv_have_getgrent_r_gnu=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getgrent_r_gnu}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETGRENT_R_GNU], [1],
        [Define to 1 if you have the 'getgrent_r' function from GNU.]
      )
    ]
  )
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETGRENT_R_SUN
#
# DESCRIPTION:
#   Check for the SunOS form of getgrent_r(), which returns a pointer rather
#   than an int.
###############################################################################

AC_DEFUN([_X_AC_GETGRENT_R_SUN], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getgrent_r (SunOS)],
    [x_ac_cv_have_getgrent_r_sun],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #include <grp.h>
          ]], [[
            struct group gr, *pgr;
            char buf[1024];
            pgr = getgrent_r (&gr, buf, sizeof buf); (void) pgr;
          ]])
        ],
        [x_ac_cv_have_getgrent_r_sun=yes],
        [x_ac_cv_have_getgrent_r_sun=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getgrent_r_sun}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETGRENT_R_SUN], [1],
        [Define to 1 if you have the 'getgrent_r' function from SunOS.]
      )
    ]
  )
])
