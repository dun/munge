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
#   For an explicit prefix, skip pkg-config, since the caller has named the
#   installation to use.  Require the OpenSSL headers and libcrypto under
#   the prefix before the link test.  The compiler and linker still search
#   their own directories, so a link test alone would accept a different
#   installation.  Look for libcrypto in "lib" and then "lib64".  OpenSSL's
#   default libdir for its linux-x86_64 target is "lib64" as of OpenSSL 3.0.0.
#
#   A preset LIBCRYPTO_CFLAGS or LIBCRYPTO_LIBS skips pkg-config and replaces
#   the value this macro would compute for that variable.  The link test
#   still runs, so a preset that does not link fails here rather than at
#   build time.  OpenSSL ships no autoconf macro, so this macro is the only
#   check on a preset.
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
#     check under PATH, which must be absolute; fail if not found
#   --without-openssl-prefix
#     do not check
#   LIBCRYPTO_CFLAGS, LIBCRYPTO_LIBS
#     use in place of the computed value; fail if the result does not link
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
  AC_ARG_VAR([LIBCRYPTO_CFLAGS], [C compiler flags for libcrypto])
  AC_ARG_VAR([LIBCRYPTO_LIBS], [linker flags for libcrypto])
  x_ac_have_libcrypto=no
  x_ac_prefix=
  x_ac_required=no

  # Fail instead of falling back when the caller named an installation or
  # supplied flags.
  AS_IF(
    [
      test "x${with_openssl_prefix}" != x \
          || test "x${LIBCRYPTO_CFLAGS}" != x \
          || test "x${LIBCRYPTO_LIBS}" != x \
    ],
    [x_ac_required=yes]
  )

  AS_IF(
    [test "x${with_openssl_prefix}" != xno],
    [
      # Dispatch on "=VALUE" so that an empty argument differs from no option.
      AS_CASE(
        ["${with_openssl_prefix+=}${with_openssl_prefix}"],
        [=yes|""],
        [
          m4_ifdef(
            [PKG_PROG_PKG_CONFIG],
            [PKG_PROG_PKG_CONFIG([0.9.0], [PKG_CONFIG="false"])]
          )
          # A preset skips pkg-config so that the link test checks it.
          AS_IF(
            [
              test "x${PKG_CONFIG}" != xfalse \
                  && test "x${PKG_CONFIG}" != x \
                  && test "x${LIBCRYPTO_CFLAGS}" = x \
                  && test "x${LIBCRYPTO_LIBS}" = x \
            ], [
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
        [=/*],
        [x_ac_prefix="${with_openssl_prefix}"],
        [
          AC_MSG_ERROR(
            [m4_normalize(
              [expected an absolute directory name for
                --with-openssl-prefix=${with_openssl_prefix}]
            )])
        ]
      )
      AS_IF(
        [test "x${x_ac_have_libcrypto}" != xyes],
        [
          # Start from the presets.  The prefix fills in only an empty one.
          x_ac_cflags="${LIBCRYPTO_CFLAGS}"
          x_ac_libs="${LIBCRYPTO_LIBS}"
          AS_IF(
            [test "x${x_ac_prefix}" != x && test "x${x_ac_cflags}" = x],
            [
              AS_IF(
                [test ! -f "${x_ac_prefix}/include/openssl/rand.h"],
                [AC_MSG_ERROR([no OpenSSL headers under "${x_ac_prefix}"])]
              )
              x_ac_cflags="-I${x_ac_prefix}/include"
            ]
          )
          AS_IF(
            [test "x${x_ac_prefix}" != x && test "x${x_ac_libs}" = x],
            [
              for x_ac_dir in lib lib64; do
                for x_ac_file in "${x_ac_prefix}/${x_ac_dir}"/libcrypto.*; do
                  if test -f "${x_ac_file}"; then
                    x_ac_libs="-L${x_ac_prefix}/${x_ac_dir} -lcrypto"
                    break 2
                  fi
                done
              done
              AS_IF(
                [test "x${x_ac_libs}" = x],
                [
                  AC_MSG_ERROR(
                    [m4_normalize(
                      [no libcrypto in "${x_ac_prefix}/lib" or
                        "${x_ac_prefix}/lib64"; set LIBCRYPTO_LIBS for
                        another layout]
                    )])
                ]
              )
            ]
          )
          AS_IF([test "x${x_ac_libs}" = x], [x_ac_libs="-lcrypto"])
          AC_MSG_CHECKING([for libcrypto])
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
    [
      test "x${x_ac_have_libcrypto}" != xyes \
          && test "x${with_openssl_prefix}" != xno \
          && test "x${x_ac_required}" = xyes \
    ],
    [AC_MSG_FAILURE([failed to configure libcrypto])]
  )
])
