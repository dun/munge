###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_COND_LIB(library, function)
#
# DESCRIPTION:
#   Check whether <function> resolves by linking with <library>.
#   Define HAVE_LIB<library> in config.h, and substitute LIB<library> as
#   "-l<library>".
#
#   Leave LIBS alone, so a caller links the library only where it is needed.
#
#   Skip the check if <function> already resolves in the default link
#   environment.  LIB<library> stays unset.
###############################################################################

AC_DEFUN([X_AC_CHECK_COND_LIB], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_CACHE_CHECK(
    [whether $2 is available without -l$1],
    [x_ac_cv_lib_none_$2],
    [
      AC_LINK_IFELSE(
        [AC_LANG_CALL([], [$2])],
        [x_ac_cv_lib_none_$2=yes],
        [x_ac_cv_lib_none_$2=no]
      )
    ]
  )
  AS_IF(
    [test "x${x_ac_cv_lib_none_$2}" = xno],
    [
      AC_CHECK_LIB(
        [$1],
        [$2],
        [
          AS_TR_CPP([LIB$1])="-l$1"
          AC_SUBST(AS_TR_CPP([LIB$1]))
          AC_DEFINE_UNQUOTED(
            AS_TR_CPP([HAVE_LIB$1]), [1],
            [Define to 1 if you have the '$1' library (-l$1).]
          )
        ]
      )
    ]
  )
])
