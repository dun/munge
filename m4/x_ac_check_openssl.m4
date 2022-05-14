#******************************************************************************
#  AUTHOR:
#    Chris Dunlap <cdunlap@llnl.gov>
#
#  SYNOPSIS:
#    X_AC_CHECK_OPENSSL
#
#  DESCRIPTION:
#    Check for OpenSSL behavior.
#
#  NOTES:
#    This must be called after X_AC_PATH_OPENSSL since it depends on the
#    makefile variables OPENSSL_CFLAGS and OPENSSL_LIBS.
#******************************************************************************

AC_DEFUN([X_AC_CHECK_OPENSSL], [
  ac_save_CFLAGS="${CFLAGS}"
  ac_save_LIBS="${LIBS}"
  CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
  LIBS="${LIBS} ${OPENSSL_LIBS}"
  AC_CHECK_FUNCS( \
    CRYPTO_THREADID_set_callback \
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
  CFLAGS="${ac_save_CFLAGS}"
  LIBS="${ac_save_LIBS}"
  ]
)

# _X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT (name, args, includes)
#
# Checks whether function <NAME> returns an integer result, and defines
#   the C preprocessor macro for HAVE_<NAME>_RETURN_INT accordingly.
# The <ARGS> are the argument list for the test function <NAME>,
#   and the <INCLUDES> are the prologue of the test source to be linked.
# The AC_LANG_PROGRAM #undef in the preamble is needed to thwart #define
#   macros used for backwards-compatibility of deprecated functions.
#
AC_DEFUN([_X_AC_CHECK_OPENSSL_FUNC_RETURNS_INT], [
  AC_CACHE_CHECK(
    [if $1 returns int],
    [ac_cv_func_$1_returns_int], [
    AS_VAR_SET([ac_cv_func_$1_returns_int], no)
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM(
        [[
$3
#undef $1
]],
        [[int rv = $1 ($2);]]
      )],
      AS_VAR_SET([ac_cv_func_$1_returns_int], yes),
      AS_VAR_SET([ac_cv_func_$1_returns_int], no)
    )]
  )
  AS_IF(
    [test AS_VAR_GET([ac_cv_func_$1_returns_int]) = yes],
    AC_DEFINE(AS_TR_CPP([HAVE_$1_RETURN_INT]), [1],
      [Define to 1 if the `$1' function returns int.]
    )
  )]
)
