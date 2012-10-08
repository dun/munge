#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_GETPWNAM
#
#  DESCRIPTION:
#    Check what forms of getpwnam() & getpwnam_r() are supported.
#******************************************************************************

AC_DEFUN([X_AC_GETPWNAM], [
  AC_CHECK_FUNCS(getpwnam)
  _X_AC_GETPWNAM_R_AIX
  _X_AC_GETPWNAM_R_POSIX
  _X_AC_GETPWNAM_R_SUN
])

AC_DEFUN([_X_AC_GETPWNAM_R_AIX], [
  AC_CACHE_CHECK(
    [for getpwnam_r (AIX)],
    [x_ac_cv_have_getpwnam_r_aix], [
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#undef _ALL_SOURCE                      /* for overriding POSIX getpwnam_r */
#define _THREAD_SAFE 1
#define _UNIX95 1
#define _XOPEN_SOURCE_EXTENDED 1
#include <pwd.h>
]],
[[
int rv;
char *user;
struct passwd pw;
char pw_buf [1024];
rv = getpwnam_r (user, &pw, pw_buf, sizeof (pw_buf)); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getpwnam_r_aix, yes),
      AS_VAR_SET(x_ac_cv_have_getpwnam_r_aix, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getpwnam_r_aix) = yes],
    AC_DEFINE([HAVE_GETPWNAM_R_AIX], [1],
      [Define to 1 if you have the `getpwnam_r' function from AIX.]
    )
  )]
)

AC_DEFUN([_X_AC_GETPWNAM_R_POSIX], [
  AC_CACHE_CHECK(
    [for getpwnam_r (POSIX)],
    [x_ac_cv_have_getpwnam_r_posix], [
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#define _POSIX_PTHREAD_SEMANTICS 1      /* for SunOS */
#include <pwd.h>
]],
[[
int rv;
char *user;
struct passwd pw, *pw_ptr;
char pw_buf [1024];
rv = getpwnam_r (user, &pw, pw_buf, sizeof (pw_buf), &pw_ptr); ]]
      )],
      AC_RUN_IFELSE([
        AC_LANG_PROGRAM([[
#define _POSIX_PTHREAD_SEMANTICS 1      /* for SunOS */
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
]],
[[
int rv;
char *user = "root";
struct passwd pw, *pw_ptr;
char pw_buf;
rv = getpwnam_r (user, &pw, &pw_buf, sizeof (pw_buf), &pw_ptr);
return ((rv == ERANGE || errno == ERANGE) ? EXIT_SUCCESS : EXIT_FAILURE); ]]
        )],
        AS_VAR_SET(x_ac_cv_have_getpwnam_r_posix, yes),
        AS_VAR_SET(x_ac_cv_have_getpwnam_r_posix, broken),
        AS_VAR_SET(x_ac_cv_have_getpwnam_r_posix, yes)),
      AS_VAR_SET(x_ac_cv_have_getpwnam_r_posix, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getpwnam_r_posix) = yes],
    AC_DEFINE([HAVE_GETPWNAM_R_POSIX], [1],
      [Define to 1 if you have the `getpwnam_r' function from POSIX.]
    )
  )]
)

AC_DEFUN([_X_AC_GETPWNAM_R_SUN], [
  AC_CACHE_CHECK(
    [for getpwnam_r (SunOS)],
    [x_ac_cv_have_getpwnam_r_sun], [
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#undef _POSIX_PTHREAD_SEMANTICS         /* for overriding POSIX getpwnam_r */
#include <pwd.h>
]],
[[
char *user;
struct passwd pw, *pw_ptr;
char pw_buf [1024];
pw_ptr = getpwnam_r (user, &pw, pw_buf, sizeof (pw_buf)); ]]
      )],
      AS_VAR_SET(x_ac_cv_have_getpwnam_r_sun, yes),
      AS_VAR_SET(x_ac_cv_have_getpwnam_r_sun, no)
    )]
  )
  AS_IF([test AS_VAR_GET(x_ac_cv_have_getpwnam_r_sun) = yes],
    AC_DEFINE([HAVE_GETPWNAM_R_SUN], [1],
      [Define to 1 if you have the `getpwnam_r' function from SunOS.]
    )
  )]
)
