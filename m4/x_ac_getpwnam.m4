###############################################################################
# SYNOPSIS:
#   X_AC_GETPWNAM
#
# DESCRIPTION:
#   Check what forms of getpwnam() and getpwnam_r() are supported.
###############################################################################

AC_DEFUN([X_AC_GETPWNAM], [
  AC_CHECK_FUNCS([getpwnam])
  _X_AC_GETPWNAM_R_AIX
  _X_AC_GETPWNAM_R_POSIX
  _X_AC_GETPWNAM_R_SUN
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETPWNAM_R_AIX
#
# DESCRIPTION:
#   Check for the AIX form of getpwnam_r(), which has 4 parameters.
###############################################################################

AC_DEFUN([_X_AC_GETPWNAM_R_AIX], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getpwnam_r (AIX)],
    [x_ac_cv_have_getpwnam_r_aix],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #undef _ALL_SOURCE                  /* override POSIX getpwnam_r */
            #define _THREAD_SAFE 1
            #define _UNIX95 1
            #define _XOPEN_SOURCE_EXTENDED 1
            #include <pwd.h>
          ]], [[
            int rv;
            char *user;
            struct passwd pw;
            char buf[1024];
            rv = getpwnam_r (user, &pw, buf, sizeof buf);
          ]])
        ],
        [x_ac_cv_have_getpwnam_r_aix=yes],
        [x_ac_cv_have_getpwnam_r_aix=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getpwnam_r_aix}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETPWNAM_R_AIX], [1],
        [Define to 1 if you have the 'getpwnam_r' function from AIX.]
      )
    ]
  )
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETPWNAM_R_POSIX
#
# DESCRIPTION:
#   Check for the POSIX form of getpwnam_r(), which has 5 parameters.
###############################################################################

AC_DEFUN([_X_AC_GETPWNAM_R_POSIX], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getpwnam_r (POSIX)],
    [x_ac_cv_have_getpwnam_r_posix],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #define _POSIX_PTHREAD_SEMANTICS 1  /* SunOS */
            #include <pwd.h>
          ]], [[
            int rv;
            char *user;
            struct passwd pw, *ppw;
            char buf[1024];
            rv = getpwnam_r (user, &pw, buf, sizeof buf, &ppw);
          ]])
        ],
        [
          AC_RUN_IFELSE(
            [
              AC_LANG_PROGRAM([[
            #define _POSIX_PTHREAD_SEMANTICS 1  /* SunOS */
            #include <errno.h>
            #include <pwd.h>
            #include <stdlib.h>
              ]], [[
                int rv;
                char *user = "root";
                struct passwd pw, *ppw;
                char buf;
                rv = getpwnam_r (user, &pw, &buf, sizeof buf, &ppw);
                return (rv == ERANGE || errno == ERANGE)
                  ? EXIT_SUCCESS
                  : EXIT_FAILURE;
              ]])
            ],
            [x_ac_cv_have_getpwnam_r_posix=yes],
            [x_ac_cv_have_getpwnam_r_posix=broken],
            [x_ac_cv_have_getpwnam_r_posix=yes]
          )
        ],
        [x_ac_cv_have_getpwnam_r_posix=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getpwnam_r_posix}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETPWNAM_R_POSIX], [1],
        [Define to 1 if you have the 'getpwnam_r' function from POSIX.]
      )
    ]
  )
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETPWNAM_R_SUN
#
# DESCRIPTION:
#   Check for the SunOS form of getpwnam_r(), which returns a pointer rather
#   than an int.
###############################################################################

AC_DEFUN([_X_AC_GETPWNAM_R_SUN], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getpwnam_r (SunOS)],
    [x_ac_cv_have_getpwnam_r_sun],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #undef _POSIX_PTHREAD_SEMANTICS     /* override POSIX getpwnam_r */
            #include <pwd.h>
          ]], [[
            char *user;
            struct passwd pw, *ppw;
            char buf[1024];
            ppw = getpwnam_r (user, &pw, buf, sizeof buf);
          ]])
        ],
        [x_ac_cv_have_getpwnam_r_sun=yes],
        [x_ac_cv_have_getpwnam_r_sun=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getpwnam_r_sun}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETPWNAM_R_SUN], [1],
        [Define to 1 if you have the 'getpwnam_r' function from SunOS.]
      )
    ]
  )
])
