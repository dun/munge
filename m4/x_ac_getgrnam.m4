#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_GETGRNAM
#
#  DESCRIPTION:
#    Check what forms of getgrnam() & getgrnam_r() are supported.
#    Based on x_ac_getpwnam.m4.
#******************************************************************************

AC_DEFUN([X_AC_GETGRNAM], [
  AC_CHECK_FUNCS(getgrnam)
  _X_AC_GETGRNAM_R_POSIX
  _X_AC_GETGRNAM_R_SUN
])

AC_DEFUN([_X_AC_GETGRNAM_R_POSIX], [
  AC_CACHE_CHECK(
    [for getgrnam_r (POSIX)],
    [x_ac_cv_have_getgrnam_r_posix], [
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#define _POSIX_PTHREAD_SEMANTICS 1      /* for SunOS */
#include <grp.h>
]],
[[
int rv;
char *name;
struct group gr, *gr_ptr;
char gr_buf [1024];
rv = getgrnam_r (name, &gr, gr_buf, sizeof (gr_buf), &gr_ptr); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getgrnam_r_posix, yes),
      AS_VAR_SET(x_ac_cv_have_getgrnam_r_posix, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getgrnam_r_posix) = yes],
    AC_DEFINE([HAVE_GETGRNAM_R_POSIX], [1],
      [Define to 1 if you have the `getgrnam_r' function from POSIX.]
    )
  )]
)

AC_DEFUN([_X_AC_GETGRNAM_R_SUN], [
  AC_CACHE_CHECK(
    [for getgrnam_r (SunOS)],
    [x_ac_cv_have_getgrnam_r_sun], [
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#undef _POSIX_PTHREAD_SEMANTICS         /* for overriding POSIX getgrnam_r */
#include <grp.h>
]],
[[
char *name;
struct group gr, *gr_ptr;
char gr_buf [1024];
gr_ptr = getgrnam_r (name, &gr, gr_buf, sizeof (gr_buf)); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getgrnam_r_sun, yes),
      AS_VAR_SET(x_ac_cv_have_getgrnam_r_sun, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getgrnam_r_sun) = yes],
    AC_DEFINE([HAVE_GETGRNAM_R_SUN], [1],
      [Define to 1 if you have the `getgrnam_r' function from SunOS.]
    )
  )]
)
