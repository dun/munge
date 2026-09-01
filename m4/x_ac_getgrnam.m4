###############################################################################
# SYNOPSIS:
#   X_AC_GETGRNAM
#
# DESCRIPTION:
#   Check what forms of getgrnam() and getgrnam_r() are supported.
###############################################################################

AC_DEFUN([X_AC_GETGRNAM], [
  AC_CHECK_FUNCS([getgrnam])
  _X_AC_GETGRNAM_R_POSIX
  _X_AC_GETGRNAM_R_SUN
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETGRNAM_R_POSIX
#
# DESCRIPTION:
#   Check for the POSIX form of getgrnam_r(), which returns an int.
###############################################################################

AC_DEFUN([_X_AC_GETGRNAM_R_POSIX], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getgrnam_r (POSIX)],
    [x_ac_cv_have_getgrnam_r_posix],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #define _POSIX_PTHREAD_SEMANTICS 1  /* SunOS */
            #include <grp.h>
          ]], [[
            int rv;
            char *name;
            struct group gr, *pgr;
            char buf[1024];
            rv = getgrnam_r (name, &gr, buf, sizeof buf, &pgr);
          ]])
        ],
        [x_ac_cv_have_getgrnam_r_posix=yes],
        [x_ac_cv_have_getgrnam_r_posix=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getgrnam_r_posix}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETGRNAM_R_POSIX], [1],
        [Define to 1 if you have the 'getgrnam_r' function from POSIX.]
      )
    ]
  )
])

###############################################################################
# SYNOPSIS:
#   _X_AC_GETGRNAM_R_SUN
#
# DESCRIPTION:
#   Check for the SunOS form of getgrnam_r(), which returns a pointer rather
#   than an int.
###############################################################################

AC_DEFUN([_X_AC_GETGRNAM_R_SUN], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [for getgrnam_r (SunOS)],
    [x_ac_cv_have_getgrnam_r_sun],
    [
      AC_LINK_IFELSE(
        [
          AC_LANG_PROGRAM([[
            #undef _POSIX_PTHREAD_SEMANTICS     /* override POSIX getgrnam_r */
            #include <grp.h>
          ]], [[
            char *name;
            struct group gr, *pgr;
            char buf[1024];
            pgr = getgrnam_r (name, &gr, buf, sizeof buf);
          ]])
        ],
        [x_ac_cv_have_getgrnam_r_sun=yes],
        [x_ac_cv_have_getgrnam_r_sun=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_have_getgrnam_r_sun}" = xyes],
    [
      AC_DEFINE(
        [HAVE_GETGRNAM_R_SUN], [1],
        [Define to 1 if you have the 'getgrnam_r' function from SunOS.]
      )
    ]
  )
])
