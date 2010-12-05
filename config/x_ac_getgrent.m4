##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_GETGRENT
#
#  DESCRIPTION:
#    Check what forms of getgrent() & getgrent_r() are supported.
#
#  NOTES:
#    The C "Werror" flag is enabled to treat compiler warnings as errors.
#    This is needed since the getgrent_r() prototypes for AIX and POSIX differ
#    only in the pointer type of the 4th argument (which is reported as a
#    compiler warning).
#
#    AC_LINK_IFELSE is used instead of AC_COMPILE_IFELSE since these tests
#    compile successfully on BSD systems without getgrent_r() implementations.
#    The missing getgrent_r() is detected when linking.
##*****************************************************************************

AC_DEFUN([X_AC_GETGRENT], [
  AC_CHECK_FUNCS(getgrent)
  _X_AC_GETGRENT_R_AIX
  _X_AC_GETGRENT_R_POSIX
  _X_AC_GETGRENT_R_SUN
])

AC_DEFUN([_X_AC_GETGRENT_R_AIX], [
  AC_CACHE_CHECK(
    [for getgrent_r (AIX)],
    [x_ac_cv_have_getgrent_r_aix], [
    _x_ac_getgrent_r_aix_c_werror_flag="$ac_c_werror_flag"
    ac_c_werror_flag=yes
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#define _THREAD_SAFE 1
#include <grp.h>
#include <stdio.h>
]],
[[
int rv;
struct group gr;
char gr_buf [1024];
FILE *gr_fp;
rv = getgrent_r (&gr, gr_buf, sizeof (gr_buf), &gr_fp); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getgrent_r_aix, yes),
      AS_VAR_SET(x_ac_cv_have_getgrent_r_aix, no)
    )
    ac_c_werror_flag="$_x_ac_getgrent_r_aix_c_werror_flag"]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getgrent_r_aix) = yes],
    AC_DEFINE([HAVE_GETGRENT_R_AIX], [1],
      [Define to 1 if you have the `getgrent_r' function from AIX.]
    )
  )]
)

AC_DEFUN([_X_AC_GETGRENT_R_POSIX], [
  AC_CACHE_CHECK(
    [for getgrent_r (POSIX)],
    [x_ac_cv_have_getgrent_r_posix], [
    _x_ac_getgrent_r_posix_c_werror_flag="$ac_c_werror_flag"
    ac_c_werror_flag=yes
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#define _GNU_SOURCE 1
#include <grp.h>
]],
[[
int rv;
struct group gr, *gr_ptr;
char gr_buf [1024];
rv = getgrent_r (&gr, gr_buf, sizeof (gr_buf), &gr_ptr); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getgrent_r_posix, yes),
      AS_VAR_SET(x_ac_cv_have_getgrent_r_posix, no)
    )
    ac_c_werror_flag="$_x_ac_getgrent_r_posix_c_werror_flag"]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getgrent_r_posix) = yes],
    AC_DEFINE([HAVE_GETGRENT_R_POSIX], [1],
      [Define to 1 if you have the `getgrent_r' function from POSIX.]
    )
  )]
)

AC_DEFUN([_X_AC_GETGRENT_R_SUN], [
  AC_CACHE_CHECK(
    [for getgrent_r (Sun)],
    [x_ac_cv_have_getgrent_r_sun], [
    _x_ac_getgrent_r_sun_c_werror_flag="$ac_c_werror_flag"
    ac_c_werror_flag=yes
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#include <grp.h>
]],
[[
struct group gr, *gr_ptr;
char gr_buf [1024];
gr_ptr = getgrent_r (&gr, gr_buf, sizeof (gr_buf)); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getgrent_r_sun, yes),
      AS_VAR_SET(x_ac_cv_have_getgrent_r_sun, no)
    )
    ac_c_werror_flag="$_x_ac_getgrent_r_sun_c_werror_flag"]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getgrent_r_sun) = yes],
    AC_DEFINE([HAVE_GETGRENT_R_SUN], [1],
      [Define to 1 if you have the `getgrent_r' function from Sun.]
    )
  )]
)
