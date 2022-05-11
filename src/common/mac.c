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
mac_map_enum (munge_mac_t mac, void *dst)
{
    return (md_map_enum (mac, dst));
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

    if (md_map_enum (md, &algo) < 0) {
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

    if (md_map_enum (md, &algo) < 0) {
        return (-1);
    }
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

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  Private Functions (OpenSSL)
 *****************************************************************************/

#if HAVE_OPENSSL

#include <openssl/evp.h>
#include <openssl/hmac.h>

static int
_mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen)
{
    EVP_MD *algo;

    if (md_map_enum (md, &algo) < 0) {
        return (-1);
    }
#if HAVE_HMAC_CTX_NEW
    /*  OpenSSL >= 1.1.0  */
    x->ctx = HMAC_CTX_new ();
#else  /* !HAVE_HMAC_CTX_NEW */
    x->ctx = OPENSSL_malloc (sizeof (HMAC_CTX));
#if HAVE_HMAC_CTX_INIT
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    if (x->ctx != NULL) {
        HMAC_CTX_init (x->ctx);
    }
#endif /* HAVE_HMAC_CTX_INIT */
#endif /* !HAVE_HMAC_CTX_NEW */
    if (x->ctx == NULL) {
        return (-1);
    }

#if HAVE_HMAC_INIT_EX_RETURN_INT
    /*  OpenSSL >= 1.0.0  */
    if (HMAC_Init_ex (x->ctx, key, keylen, algo, NULL) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_INIT_EX
    /*  OpenSSL >= 0.9.7, < 1.0.0  */
    HMAC_Init_ex (x->ctx, key, keylen, algo, NULL);
#elif HAVE_HMAC_INIT
    /*  HMAC_Init() implicitly initializes the HMAC_CTX.  */
    /*  OpenSSL >= 0.9.0  */
    HMAC_Init (x->ctx, key, keylen, algo);
#else  /* !HAVE_HMAC_INIT */
#error "No OpenSSL HMAC_Init"
#endif /* !HAVE_HMAC_INIT */

    x->diglen = EVP_MD_size (algo);
    return (0);
}


static int
_mac_update (mac_ctx *x, const void *src, int srclen)
{
#if HAVE_HMAC_UPDATE_RETURN_INT
    /*  OpenSSL >= 1.0.0  */
    if (HMAC_Update (x->ctx, src, srclen) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_UPDATE
    /*  OpenSSL >= 0.9.0, < 1.0.0  */
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
#if HAVE_HMAC_FINAL_RETURN_INT
    /*  OpenSSL >= 1.0.0  */
    if (HMAC_Final (x->ctx, dst, (unsigned int *) dstlenp) != 1) {
        return (-1);
    }
#elif HAVE_HMAC_FINAL
    /*  OpenSSL >= 0.9.0, < 1.0.0  */
    HMAC_Final (x->ctx, dst, (unsigned int *) dstlenp);
#else  /* !HAVE_HMAC_FINAL */
#error "No OpenSSL HMAC_Final"
#endif /* !HAVE_HMAC_FINAL */

    return (0);
}


static int
_mac_cleanup (mac_ctx *x)
{
#if HAVE_HMAC_CTX_FREE
    /*  OpenSSL >= 1.1.0  */
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
    EVP_MD *algo;

    if (md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    if (*dstlenp < EVP_MD_size (algo)) {
        return (-1);
    }
    if (!HMAC (algo, key, keylen, src, srclen, dst, (unsigned int *)dstlenp)) {
        return (-1);
    }
    return (0);
}

#endif /* HAVE_OPENSSL */
