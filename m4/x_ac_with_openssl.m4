###############################################################################
# SYNOPSIS:
#   X_AC_WITH_OPENSSL
#
# DESCRIPTION:
#   Check for the OpenSSL libcrypto library and set LIBCRYPTO_CFLAGS and
#   LIBCRYPTO_LIBS.  Query pkg-config when it is available.  If pkg-config
#   is unavailable or does not find libcrypto, link a test program against
#   libcrypto.
#
#   For an explicit prefix, skip pkg-config and use only the link test,
#   since the caller has named the installation to use.
#
#   The link test is not cached.  Its result depends on
#   "--with-openssl-prefix", which "config.cache" does not record,
#   so a cached result could outlive a change to the prefix.
#
# USAGE:
#   unspecified (default)
#     check with pkg-config, then in the standard path
#   --with-openssl-prefix
#     check with pkg-config, then in the standard path; fail if not found
#   --with-openssl-prefix=PATH
#     skip pkg-config and search PATH first; PATH must be absolute
#   --without-openssl-prefix
#     do not check
###############################################################################

AC_DEFUN_ONCE([X_AC_WITH_OPENSSL], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_ARG_WITH(
    [openssl-prefix],
    [AS_HELP_STRING(
      [--with-openssl-prefix=PATH],
      [prefix where OpenSSL is installed]
    )]dnl
  )
  x_ac_have_libcrypto=no
  x_ac_prefix=

  AS_IF(
    [test "x${withval}" != xno],
    [
      AS_IF(
        [test "x${withval}" = xyes || test "x${withval}" = x],
        [
          m4_ifdef(
            [PKG_PROG_PKG_CONFIG],
            [PKG_PROG_PKG_CONFIG([0.9.0], [PKG_CONFIG="false"])]
          )
          AS_IF(
            [test "x${PKG_CONFIG}" != xfalse],
            [
              m4_ifdef(
                [PKG_CHECK_MODULES],
                [
                  PKG_CHECK_MODULES(
                    [LIBCRYPTO], [libcrypto], [x_ac_have_libcrypto=yes], [:]
                  )
                ],
                [:]
              )
            ]
          )
        ],
        [expr match "${withval}" "[[^/]]" >/dev/null],
        [
          AC_MSG_ERROR(
            [m4_normalize(
              [expected an absolute directory name for
                --with-openssl-prefix=${withval}]
            )])
        ],
        [x_ac_prefix="${withval}"]
      )
      AS_IF(
        [test "x${x_ac_have_libcrypto}" != xyes],
        [
          AC_MSG_CHECKING([for libcrypto])
          x_ac_cflags=
          x_ac_libs="-lcrypto"
          AS_IF(
            [test "x${x_ac_prefix}" != x],
            [
              x_ac_cflags="-I${x_ac_prefix}/include ${x_ac_cflags}"
              x_ac_libs="-L${x_ac_prefix}/lib ${x_ac_libs}"
            ]
          )
          x_ac_save_CFLAGS="${CFLAGS}"
          x_ac_save_LIBS="${LIBS}"
          CFLAGS="${x_ac_cflags} ${CFLAGS}"
          LIBS="${x_ac_libs} ${LIBS}"
          AC_LINK_IFELSE(
            [
              AC_LANG_PROGRAM(
                [[#include <openssl/rand.h>]],
                [[(void) RAND_bytes (NULL, 0);]]
              )
            ], [
              LIBCRYPTO_CFLAGS="${x_ac_cflags}"
              LIBCRYPTO_LIBS="${x_ac_libs}"
              x_ac_have_libcrypto=yes
            ]
          )
          CFLAGS="${x_ac_save_CFLAGS}"
          LIBS="${x_ac_save_LIBS}"
          AC_MSG_RESULT([${x_ac_have_libcrypto}])
        ]
      )
    ]
  )
  AC_SUBST([LIBCRYPTO_CFLAGS])
  AC_SUBST([LIBCRYPTO_LIBS])
  AS_IF(
    [test "x${LIBCRYPTO_LIBS}" = x && test "x${withval}" = xyes],
    [AC_MSG_FAILURE([failed to configure --with-openssl-prefix])]
  )
])
