###############################################################################
# SYNOPSIS:
#   X_AC_CHECK_OPENSSL
#
# DESCRIPTION:
#   Check for OpenSSL functions, headers, and types.
###############################################################################

AC_DEFUN([X_AC_CHECK_OPENSSL], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AC_REQUIRE([X_AC_WITH_OPENSSL])[]dnl
  x_ac_save_CFLAGS="${CFLAGS}"
  x_ac_save_LIBS="${LIBS}"
  CFLAGS="${CFLAGS} ${LIBCRYPTO_CFLAGS}"
  LIBS="${LIBS} ${LIBCRYPTO_LIBS}"
  # Autoconf 2.69 and earlier interpolate this list into a shell "for" loop
  # without normalizing it.  A bracketed multi-line list is a syntax error.
  AC_CHECK_FUNCS( \
    CRYPTO_THREADID_set_callback \
    CRYPTO_memcmp \
    CRYPTO_num_locks \
    CRYPTO_set_id_callback \
    CRYPTO_set_locking_callback \
    ERR_free_strings \
    ERR_load_crypto_strings \
    EVP_CIPHER_CTX_cleanup \
    EVP_CIPHER_CTX_free \
    EVP_CIPHER_CTX_init \
    EVP_CIPHER_CTX_new \
    EVP_CipherFinal \
    EVP_CipherFinal_ex \
    EVP_CipherInit \
    EVP_CipherInit_ex \
    EVP_CipherUpdate \
    EVP_DigestFinal \
    EVP_DigestFinal_ex \
    EVP_DigestInit \
    EVP_DigestInit_ex \
    EVP_DigestUpdate \
    EVP_MAC_CTX_free \
    EVP_MAC_CTX_new \
    EVP_MAC_fetch \
    EVP_MAC_final \
    EVP_MAC_init \
    EVP_MAC_update \
    EVP_MD_CTX_cleanup \
    EVP_MD_CTX_copy \
    EVP_MD_CTX_copy_ex \
    EVP_MD_CTX_create \
    EVP_MD_CTX_destroy \
    EVP_MD_CTX_free \
    EVP_MD_CTX_init \
    EVP_MD_CTX_new \
    EVP_Q_mac \
    EVP_aes_128_cbc \
    EVP_aes_256_cbc \
    EVP_sha256 \
    EVP_sha512 \
    HMAC \
    HMAC_CTX_cleanup \
    HMAC_CTX_free \
    HMAC_CTX_init \
    HMAC_CTX_new \
    HMAC_Final \
    HMAC_Init \
    HMAC_Init_ex \
    HMAC_Update \
    HMAC_cleanup \
    RAND_cleanup \
    RAND_pseudo_bytes \
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [EVP_CIPHER_CTX_cleanup],
    [NULL],
    [#include <openssl/evp.h>]
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [EVP_CipherInit],
    [NULL, NULL, NULL, NULL, 0],
    [#include <openssl/evp.h>]
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [EVP_CipherUpdate],
    [NULL, NULL, NULL, NULL, 0],
    [#include <openssl/evp.h>]
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [EVP_DigestUpdate],
    [NULL, NULL, 0],
    [#include <openssl/evp.h>]
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [HMAC_Final],
    [NULL, NULL, NULL],
    [#include <openssl/hmac.h>]
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [HMAC_Init_ex],
    [NULL, NULL, 0, NULL, NULL],
    [#include <openssl/hmac.h>]
  )
  _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
    [HMAC_Update],
    [NULL, NULL, 0],
    [#include <openssl/hmac.h>]
  )
  # Autoconf 2.69 and earlier interpolate this list into a shell "for" loop
  # without normalizing it.  A bracketed multi-line list is a syntax error.
  AC_CHECK_HEADERS( \
    openssl/core.h \
    openssl/core_names.h \
    openssl/hmac.h \
    openssl/provider.h \
  )
  AC_CHECK_TYPES([CRYPTO_dynlock], [], [], [#include <openssl/crypto.h>])
  AC_CHECK_TYPES([EVP_MAC *, EVP_MAC_CTX *], [], [], [#include <openssl/evp.h>])
  AC_CHECK_TYPES([OSSL_PARAM *], [], [], [#include <openssl/params.h>])
  AC_CHECK_TYPES([OSSL_PROVIDER *], [], [], [#include <openssl/provider.h>])
  CFLAGS="${x_ac_save_CFLAGS}"
  LIBS="${x_ac_save_LIBS}"
])

###############################################################################
# SYNOPSIS:
#   _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(name, args, includes)
#
# DESCRIPTION:
#   Check whether the OpenSSL function <name> returns int, and if so, define
#   HAVE_<name>_RETURN_INT in config.h.  <args> is the argument list for the
#   test call, and <includes> is the required header prologue.
#
#   Insert an #undef of <name> after the includes, so a backward-compatibility
#   macro cannot interfere with the return-type check.
#
#   Skip the check unless AC_CHECK_FUNCS has confirmed <name> exists.  A
#   missing function would otherwise produce an implicit-declaration warning.
#
# USAGE:
#   Probe a function that AC_CHECK_FUNCS has already checked:
#
#     _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT(
#       [HMAC_Update],
#       [NULL, NULL, 0],
#       [#include <openssl/hmac.h>]
#     )
#
#   <args> is a bare argument list for the call.  Every argument may be
#   NULL or 0.  The program is linked but never run.
###############################################################################

AC_DEFUN([_X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT], [
  AC_REQUIRE([AC_PROG_CC])[]dnl
  AS_IF(
    [test "x${ac_cv_func_$1}" = xyes],
    [
      AC_CACHE_CHECK(
        [if $1 returns int],
        [x_ac_cv_have_$1_return_int],
        [
          x_ac_cv_have_$1_return_int=no
          AC_LINK_IFELSE(
            [
              AC_LANG_PROGRAM([[
                $3
                #undef $1
              ]], [[
                int rv = $1 ($2);
              ]])
            ],
            [x_ac_cv_have_$1_return_int=yes],
            [x_ac_cv_have_$1_return_int=no]
          )
        ]
      )
      AS_IF(
        [test "x${x_ac_cv_have_$1_return_int}" = xyes],
        [
          AC_DEFINE(
            AS_TR_CPP([HAVE_$1_RETURN_INT]), [1],
            [Define to 1 if the '$1' function returns int.]
          )
        ]
      )
    ]
  )
])
