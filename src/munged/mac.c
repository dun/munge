/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <string.h>
#include "mac.h"
#include "md.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MAC_MAGIC 0xDEADACE2


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static int _mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen);
static int _mac_update (mac_ctx *x, const void *src, int srclen);
static int _mac_final (mac_ctx *x, void *dst, int *dstlen);
static int _mac_cleanup (mac_ctx *x);
static int _mac_block (munge_mac_t md, const void *key, int keylen,
    void *dst, int *dstlen, const void *src, int srclen);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

int
mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen)
{
    int rc;

    assert (x != NULL);
    assert (key != NULL);
    assert (keylen > 0);

    rc = _mac_init (x, md, key, keylen);
    if (rc >= 0) {
        assert (x->magic = MAC_MAGIC);
        assert (!(x->finalized = 0));
    }
    return (rc);
}


int
mac_update (mac_ctx *x, const void *src, int srclen)
{
    int rc;

    assert (x != NULL);
    assert (x->magic == MAC_MAGIC);
    assert (x->finalized != 1);
    assert (src != NULL);

    if (srclen <= 0) {
        return (0);
    }
    rc = _mac_update (x, src, srclen);
    return (rc);
}


int
mac_final (mac_ctx *x, void *dst, int *dstlen)
{
    int rc;

    assert (x != NULL);
    assert (x->magic == MAC_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);
    assert (dstlen != NULL);

    if ((dstlen == NULL) || (*dstlen <= 0)) {
        return (-1);
    }
    rc = _mac_final (x, dst, dstlen);
    assert (x->finalized = 1);
    return (rc);
}


int
mac_cleanup (mac_ctx *x)
{
    int rc;

    assert (x != NULL);
    assert (x->magic == MAC_MAGIC);

    rc = _mac_cleanup (x);
    memset (x, 0, sizeof (*x));
    assert (x->magic = ~MAC_MAGIC);
    return (rc);
}


int
mac_size (munge_mac_t md)
{
    return (md_size (md));
}


int
mac_block (munge_mac_t md, const void *key, int keylen,
           void *dst, int *dstlen, const void *src, int srclen)
{
    int rc;

    assert (key != NULL);
    assert (src != NULL);
    assert (dst != NULL);
    assert (dstlen != NULL);

    if (srclen <= 0) {
        *dstlen = 0;
        return (0);
    }
    rc = _mac_block (md, key, keylen, dst, dstlen, src, srclen);
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
        log_msg (LOG_DEBUG, "gcry_md_open failed for mac=%d hmac: %s",
            md, gcry_strerror (e));
        return (-1);
    }
    if ((e = gcry_md_setkey (x->ctx, key, keylen)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_setkey failed for mac=%d hmac: %s",
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
_mac_final (mac_ctx *x, void *dst, int *dstlen)
{
    unsigned char *digest;

    if (*dstlen < x->diglen) {
        return (-1);
    }
    if ((digest = gcry_md_read (x->ctx, 0)) == NULL) {
        return (-1);
    }
    memcpy (dst, digest, x->diglen);
    *dstlen = x->diglen;
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
            void *dst, int *dstlen, const void *src, int srclen)
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
    if (*dstlen < len) {
        return (-1);
    }
    if ((e = gcry_md_open (&ctx, algo, GCRY_MD_FLAG_HMAC)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_open failed for mac=%d hmac: %s",
            md, gcry_strerror (e));
        return (-1);
    }
    if ((e = gcry_md_setkey (ctx, key, keylen)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_setkey failed for mac=%d hmac: %s",
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
    *dstlen = len;
    gcry_md_close (ctx);
    memset (&ctx, 0, sizeof (ctx));
    return (0);
}

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  Private Functions (OpenSSL)
 *****************************************************************************/
/*
 *  HMAC_Init() implicitly initializes the HMAC_CTX.
 *    This call has been deprecated as of OpenSSL 0.9.7.
 *  If HMAC_Init_ex() exists, so should HMAC_CTX_init() & HMAC_CTX_cleanup().
 */

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
#if HAVE_HMAC_INIT_EX
    HMAC_CTX_init (&(x->ctx));
    HMAC_Init_ex (&(x->ctx), key, keylen, algo, NULL);
#else  /* !HAVE_HMAC_INIT_EX */
    HMAC_Init (&(x->ctx), key, keylen, algo);
#endif /* !HAVE_HMAC_INIT_EX */
    x->diglen = EVP_MD_size (algo);
    return (0);
}


static int
_mac_update (mac_ctx *x, const void *src, int srclen)
{
    HMAC_Update (&(x->ctx), src, srclen);
    return (0);
}


static int
_mac_final (mac_ctx *x, void *dst, int *dstlen)
{
    if (*dstlen < x->diglen) {
        return (-1);
    }
    HMAC_Final (&(x->ctx), dst, (unsigned int *) dstlen);
    return (0);
}


static int
_mac_cleanup (mac_ctx *x)
{
#if HAVE_HMAC_INIT_EX
    HMAC_CTX_cleanup (&(x->ctx));
#else  /* !HAVE_HMAC_INIT_EX */
    HMAC_cleanup (&(x->ctx));
#endif /* !HAVE_HMAC_INIT_EX */
    return (0);
}


static int
_mac_block (munge_mac_t md, const void *key, int keylen,
            void *dst, int *dstlen, const void *src, int srclen)
{
    EVP_MD *algo;

    if (md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    if (*dstlen < EVP_MD_size (algo)) {
        return (-1);
    }
    HMAC (algo, key, keylen, src, srclen, dst, (unsigned int *) dstlen);
    return (0);
}

#endif /* HAVE_OPENSSL */
