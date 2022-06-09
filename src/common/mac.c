/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2022 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://dun.github.io/munge/>.
 *
 *  MUNGE is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation, either version 3 of the License, or (at your option)
 *  any later version.  Additionally for the MUNGE library (libmunge), you
 *  can redistribute it and/or modify it under the terms of the GNU Lesser
 *  General Public License as published by the Free Software Foundation,
 *  either version 3 of the License, or (at your option) any later version.
 *
 *  MUNGE is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  and GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  and GNU Lesser General Public License along with MUNGE.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <string.h>
#include "mac.h"
#include "md.h"


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static int _mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen);
static int _mac_update (mac_ctx *x, const void *src, int srclen);
static int _mac_final (mac_ctx *x, void *dst, int *dstlenp);
static int _mac_cleanup (mac_ctx *x);
static int _mac_block (munge_mac_t md, const void *key, int keylen,
    void *dst, int *dstlenp, const void *src, int srclen);
static int _mac_map_enum (munge_mac_t md, void *dst);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

int
mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen)
{
    int rc;

    if (!x || !key || (keylen < 0)) {
        return (-1);
    }
    rc = _mac_init (x, md, key, keylen);
    return (rc);
}


int
mac_update (mac_ctx *x, const void *src, int srclen)
{
    int rc;

    if (!x || !src || (srclen < 0)) {
        return (-1);
    }
    rc = _mac_update (x, src, srclen);
    return (rc);
}


int
mac_final (mac_ctx *x, void *dst, int *dstlenp)
{
    int rc;

    if (!x || !dst || !dstlenp) {
        return (-1);
    }
    rc = _mac_final (x, dst, dstlenp);
    return (rc);
}


int
mac_cleanup (mac_ctx *x)
{
    int rc;

    if (!x) {
        return (-1);
    }
    rc = _mac_cleanup (x);
    memset (x, 0, sizeof (*x));
    return (rc);
}


int
mac_size (munge_mac_t md)
{
    return (md_size (md));
}


int
mac_block (munge_mac_t md, const void *key, int keylen,
           void *dst, int *dstlenp, const void *src, int srclen)
{
    int rc;

    if (!key || (keylen < 0) || !dst || !dstlenp || !src || (srclen < 0)) {
        return (-1);
    }
    rc = _mac_block (md, key, keylen, dst, dstlenp, src, srclen);
    return (rc);
}


int
mac_map_enum (munge_mac_t md, void *dst)
{
    if ((md <= MUNGE_MAC_DEFAULT) || (md >= MUNGE_MAC_LAST_ITEM)) {
        return (-1);
    }
    return (_mac_map_enum (md, dst));
}


/*****************************************************************************
 *  Private Functions (Libgcrypt)
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>
#include "log.h"

static int
_mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen)
{
    gcry_error_t e;
    int          algo;

    if (_mac_map_enum (md, &algo) < 0) {
        return (-1);
    }
    if ((e = gcry_md_open (&(x->ctx), algo, GCRY_MD_FLAG_HMAC)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_open failed for MAC=%d HMAC: %s",
            md, gcry_strerror (e));
        return (-1);
    }
    if ((e = gcry_md_setkey (x->ctx, key, keylen)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_setkey failed for MAC=%d HMAC: %s",
            md, gcry_strerror (e));
        return (-1);
    }
    /*  Bypass mac_size() since md->algo mapping has already been computed.
     */
    x->diglen = gcry_md_get_algo_dlen (algo);
    return (0);
}


static int
_mac_update (mac_ctx *x, const void *src, int srclen)
{
    gcry_md_write (x->ctx, src, srclen);
    return (0);
}


static int
_mac_final (mac_ctx *x, void *dst, int *dstlenp)
{
    unsigned char *digest;

    if (*dstlenp < x->diglen) {
        return (-1);
    }
    if ((digest = gcry_md_read (x->ctx, 0)) == NULL) {
        return (-1);
    }
    memcpy (dst, digest, x->diglen);
    *dstlenp = x->diglen;
    return (0);
}


static int
_mac_cleanup (mac_ctx *x)
{
    gcry_md_close (x->ctx);
    return (0);
}


static int
_mac_block (munge_mac_t md, const void *key, int keylen,
            void *dst, int *dstlenp, const void *src, int srclen)
{
    gcry_error_t   e;
    int            algo;
    int            len;
    gcry_md_hd_t   ctx;
    unsigned char *digest;

    if (_mac_map_enum (md, &algo) < 0) {
        return (-1);
    }
    /*  Bypass mac_size() since md->algo mapping has already been computed.
     */
    len = gcry_md_get_algo_dlen (algo);
    if (*dstlenp < len) {
        return (-1);
    }
    if ((e = gcry_md_open (&ctx, algo, GCRY_MD_FLAG_HMAC)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_open failed for MAC=%d HMAC: %s",
            md, gcry_strerror (e));
        return (-1);
    }
    if ((e = gcry_md_setkey (ctx, key, keylen)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_setkey failed for MAC=%d HMAC: %s",
            md, gcry_strerror (e));
        gcry_md_close (ctx);
        return (-1);
    }
    gcry_md_write (ctx, src, srclen);

    if ((digest = gcry_md_read (ctx, 0)) == NULL) {
        gcry_md_close (ctx);
        return (-1);
    }
    memcpy (dst, digest, len);
    *dstlenp = len;
    gcry_md_close (ctx);
    memset (&ctx, 0, sizeof (ctx));
    return (0);
}


int
_mac_map_enum (munge_mac_t md, void *dst)
{
    return (md_map_enum (md, dst));
}

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  Private Functions (OpenSSL)
 *****************************************************************************/

#if HAVE_OPENSSL

#include <limits.h>
#include <openssl/evp.h>

#if HAVE_OPENSSL_CORE_H
#include <openssl/core.h>
#endif /* HAVE_OPENSSL_CORE_H */

#if HAVE_OPENSSL_CORE_NAMES_H
#include <openssl/core_names.h>
#endif /* HAVE_OPENSSL_CORE_NAMES_H */

#if HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>
#endif /* HAVE_OPENSSL_HMAC_H */

static int
_mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen)
{
#if HAVE_OSSL_PARAM_P && HAVE_EVP_MAC_P
    /*  OpenSSL >= 3.0  */
    OSSL_PARAM *algo;
    EVP_MAC *mac;
#else /* !HAVE_OSSL_PARAM_P */
    /*  OpenSSL < 3.0  */
    EVP_MD *algo;
#endif /* !HAVE_OSSL_PARAM_P */

    if (_mac_map_enum (md, &algo) < 0) {
        return (-1);
    }

#if HAVE_EVP_MAC_FETCH && HAVE_EVP_MAC_CTX_NEW
    /*  OpenSSL >= 3.0  */
    mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
    if (mac == NULL) {
        return (-1);
    }
    x->ctx = EVP_MAC_CTX_new (mac);
    EVP_MAC_free (mac);
#elif HAVE_HMAC_CTX_NEW
    /*  OpenSSL >= 1.1.0, Deprecated since OpenSSL 3.0  */
    x->ctx = HMAC_CTX_new ();
#else  /* !HAVE_HMAC_CTX_NEW */
    x->ctx = OPENSSL_malloc (sizeof (HMAC_CTX));
#if HAVE_HMAC_CTX_INIT
    /*  OpenSSL >= 0.9.7, < 1.1.0, Replaced with HMAC_CTX_reset() in 1.1.0  */
    if (x->ctx != NULL) {
        HMAC_CTX_init (x->ctx);
    }
#endif /* HAVE_HMAC_CTX_INIT */
#endif /* !HAVE_HMAC_CTX_NEW */
    if (x->ctx == NULL) {
        return (-1);
    }

#if HAVE_EVP_MAC_INIT
    /*  OpenSSL >= 3.0  */
    if (EVP_MAC_init (x->ctx, key, (size_t) keylen, algo) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_INIT_EX_RETURN_INT
    /*  OpenSSL >= 1.0.0, Deprecated since OpenSSL 3.0  */
    if (HMAC_Init_ex (x->ctx, key, keylen, algo, NULL) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_INIT_EX
    /*  OpenSSL >= 0.9.7, < 1.0.0, Deprecated since OpenSSL 3.0  */
    HMAC_Init_ex (x->ctx, key, keylen, algo, NULL);
#elif HAVE_HMAC_INIT
    /*  HMAC_Init() implicitly initializes the HMAC_CTX.  */
    /*  OpenSSL >= 0.9.0, Deprecated since OpenSSL 1.1.0  */
    HMAC_Init (x->ctx, key, keylen, algo);
#else  /* !HAVE_HMAC_INIT */
#error "No OpenSSL HMAC_Init"
#endif /* !HAVE_HMAC_INIT */

    x->diglen = mac_size (md);
    return (0);
}


static int
_mac_update (mac_ctx *x, const void *src, int srclen)
{
#if HAVE_EVP_MAC_UPDATE
    /*  OpenSSL >= 3.0  */
    if (EVP_MAC_update (x->ctx, src, (size_t) srclen) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_UPDATE_RETURN_INT
    /*  OpenSSL >= 1.0.0, Deprecated since OpenSSL 3.0  */
    if (HMAC_Update (x->ctx, src, srclen) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_UPDATE
    /*  OpenSSL >= 0.9.0, < 1.0.0, Deprecated since OpenSSL 3.0  */
    HMAC_Update (x->ctx, src, srclen);
#else  /* !HAVE_HMAC_UPDATE */
#error "No OpenSSL HMAC_Update"
#endif /* !HAVE_HMAC_UPDATE */

    return (0);
}


static int
_mac_final (mac_ctx *x, void *dst, int *dstlenp)
{
    if (*dstlenp < x->diglen) {
        return (-1);
    }
#if HAVE_EVP_MAC_FINAL
    /*  OpenSSL >= 3.0  */
    size_t dstsize = (size_t) *dstlenp;
    if (EVP_MAC_final (x->ctx, dst, &dstsize, dstsize) != 1) {
        return (-1);
    }
    if (dstsize > INT_MAX) {
        return (-1);
    }
    *dstlenp = (int) dstsize;
#elif HAVE_HMAC_FINAL_RETURN_INT
    /*  OpenSSL >= 1.0.0, Deprecated since OpenSSL 3.0  */
    if (HMAC_Final (x->ctx, dst, (unsigned int *) dstlenp) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_FINAL
    /*  OpenSSL >= 0.9.0, < 1.0.0, Deprecated since OpenSSL 3.0  */
    HMAC_Final (x->ctx, dst, (unsigned int *) dstlenp);
#else  /* !HAVE_HMAC_FINAL */
#error "No OpenSSL HMAC_Final"
#endif /* !HAVE_HMAC_FINAL */

    return (0);
}


static int
_mac_cleanup (mac_ctx *x)
{
#if HAVE_EVP_MAC_CTX_FREE
    /*  OpenSSL >= 3.0  */
    EVP_MAC_CTX_free (x->ctx);
#elif HAVE_HMAC_CTX_FREE
    /*  OpenSSL >= 1.1.0, Deprecated since OpenSSL 3.0  */
    HMAC_CTX_free (x->ctx);
#else  /* !HAVE_HMAC_CTX_FREE */
#if HAVE_HMAC_CTX_CLEANUP
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    HMAC_CTX_cleanup (x->ctx);
#elif HAVE_HMAC_CLEANUP
    /*  OpenSSL >= 0.9.0, < 0.9.7  */
    HMAC_cleanup (x->ctx);
#endif /* HAVE_HMAC_CLEANUP */
    OPENSSL_free (x->ctx);
#endif /* !HAVE_HMAC_CTX_FREE */

    x->ctx = NULL;
    return (0);
}


static int
_mac_block (munge_mac_t md, const void *key, int keylen,
            void *dst, int *dstlenp, const void *src, int srclen)
{
#if HAVE_OSSL_PARAM_P
    /*  OpenSSL >= 3.0  */
    OSSL_PARAM *algo;
#else /* !HAVE_OSSL_PARAM_P */
    /*  OpenSSL < 3.0  */
    EVP_MD *algo;
#endif /* !HAVE_OSSL_PARAM_P */

    /*  OpenSSL has EVP_MD_size(const EVP_MD *md) to get the size of the
     *    message digest [md].  Converting from munge_mac_t to EVP_MD * is
     *    straightforward.
     *  OpenSSL 3.0 introduces EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx).
     *    But before that can be called, one needs to create the context via
     *    EVP_MAC_fetch() and EVP_MAC_CTX_new(), specify the underlying message
     *    digest in an OSSL_PARAM array, and initialize the context via
     *    EVP_MAC_init().  And none of that is needed with EVP_Q_mac()!
     *    So instead, mac_size() is called to abstract away any shenanigans in
     *    getting the size of the message digest [md] needed to validate the
     *    buffer size in [dstlenp].
     */
    if (*dstlenp < mac_size (md)) {
        return (-1);
    }
    if (_mac_map_enum (md, &algo) < 0) {
        return (-1);
    }
#if HAVE_EVP_Q_MAC
    /*  OpenSSL >= 3.0  */
    size_t dstsize = (size_t) *dstlenp;
    if (!EVP_Q_mac (NULL, "HMAC", NULL, NULL, algo, key, (size_t) keylen,
                src, (size_t) srclen, dst, dstsize, &dstsize)) {
        return (-1);
    }
    if (dstsize > INT_MAX) {
        return (-1);
    }
    *dstlenp = (int) dstsize;
#elif HAVE_HMAC
    /*  OpenSSL < 3.0  */
    if (!HMAC (algo, key, keylen, src, srclen, dst, (unsigned int *)dstlenp)) {
        return (-1);
    }
#else
#error "No OpenSSL single-pass HMAC routine"
#endif
    return (0);
}


int
_mac_map_enum (munge_mac_t md, void *dst)
{
#if HAVE_EVP_MAC_INIT
/*
 *  EVP_MAC_init() has a parameter of type "const OSSL_PARAM params[]",
 *    so HAVE_EVP_MAC_INIT is being used here as a proxy to detect OpenSSL 3.0
 *    API changes.
 */
    static const OSSL_PARAM param[][2] = {
        { OSSL_PARAM_END },             /* MUNGE_MAC_NONE */
        { OSSL_PARAM_END },             /* MUNGE_MAC_DEFAULT */
        { OSSL_PARAM_utf8_string (OSSL_ALG_PARAM_DIGEST, "MD5", 3),
          OSSL_PARAM_END },             /* MUNGE_MAC_MD5 */
        { OSSL_PARAM_utf8_string (OSSL_ALG_PARAM_DIGEST, "SHA1", 4),
          OSSL_PARAM_END },             /* MUNGE_MAC_SHA1 */
        { OSSL_PARAM_utf8_string (OSSL_ALG_PARAM_DIGEST, "RIPEMD160", 9),
          OSSL_PARAM_END },             /* MUNGE_MAC_RIPEMD160 */
        { OSSL_PARAM_utf8_string (OSSL_ALG_PARAM_DIGEST, "SHA2-256", 8),
          OSSL_PARAM_END },             /* MUNGE_MAC_SHA256 */
        { OSSL_PARAM_utf8_string (OSSL_ALG_PARAM_DIGEST, "SHA2-512", 8),
          OSSL_PARAM_END },             /* MUNGE_MAC_SHA512 */
    };

    if ((md < MUNGE_MAC_MD5) || (md > MUNGE_MAC_SHA512)) {
        return (-1);
    }
    if (dst != NULL) {
        * (const OSSL_PARAM **) dst = param[md];
    }
    return (0);

#else  /* !HAVE_EVP_MAC_INIT */
    return (md_map_enum (md, dst));
#endif /* !HAVE_EVP_MAC_INIT */
}

#endif /* HAVE_OPENSSL */
