###############################################################################
# SYNOPSIS:
#   X_AC_WITH_LIBGCRYPT
#
# DESCRIPTION:
#   Check for the Libgcrypt library and set LIBGCRYPT_CFLAGS and
#   LIBGCRYPT_LIBS.  Both are empty when the check fails.
#
#   The check is AM_PATH_LIBGCRYPT from "libgcrypt.m4".  Libgcrypt installs
#   that file with its headers.  If aclocal did not find that file when
#   configure was generated, this macro skips the check and prints a
#   "skipped" result.  LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS then keep the
#   values configure inherited.
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_LIBGCRYPT], [
  m4_ifdef(
    [AM_PATH_LIBGCRYPT],
    [AM_PATH_LIBGCRYPT],
    [
      AC_MSG_CHECKING([for Libgcrypt])
      AC_MSG_RESULT([skipped (aclocal did not find libgcrypt.m4)])
    ]
  )
])
