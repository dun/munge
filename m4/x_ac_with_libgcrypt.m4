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
#   configure was generated, this macro checks for nothing and leaves
#   LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS as configure inherited them.
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_LIBGCRYPT], [
  m4_ifdef([AM_PATH_LIBGCRYPT], [AM_PATH_LIBGCRYPT])
])
