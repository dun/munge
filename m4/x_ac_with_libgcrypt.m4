###############################################################################
# SYNOPSIS:
#   X_AC_WITH_LIBGCRYPT
#
# DESCRIPTION:
#   Check for the libgcrypt library.  Requires pkgconf.
#   Define LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS accordingly.
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_LIBGCRYPT],
[
  m4_ifdef([AM_PATH_LIBGCRYPT], [AM_PATH_LIBGCRYPT])
])
