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
#include <munge.h>
#include <string.h>
#include "md.h"


/*****************************************************************************
 *  Private Data
 *****************************************************************************/

static int _md_is_initialized = 0;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void _md_init_subsystem (void);
static int _md_init (md_ctx *x, munge_mac_t md);
static int _md_update (md_ctx *x, const void *src, int srclen);
static int _md_final (md_ctx *x, void *dst, int *dstlenp);
static int _md_cleanup (md_ctx *x);
static int _md_copy (md_ctx *xdst, md_ctx *xsrc);
static int _md_size (munge_mac_t md);
static int _md_map_enum (munge_mac_t md, void *dst);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
md_init_subsystem (void)
{
/*  Note that this call is *NOT* thread-safe.
 */
    if (! _md_is_initialized) {
        _md_init_subsystem ();
        _md_is_initialized++;
    }
    return;
}


int
md_init (md_ctx *x, munge_mac_t md)
{
    int rc;

    assert (_md_is_initialized);

    if (!x) {
        return (-1);
    }
    rc = _md_init (x, md);
    return (rc);
}


int
md_update (md_ctx *x, const void *src, int srclen)
{
    int rc;

    assert (_md_is_initialized);

    if (!x || !src || (srclen < 0)) {
        return (-1);
    }
    rc = _md_update (x, src, srclen);
    return (rc);
}


int
md_final (md_ctx *x, void *dst, int *dstlenp)
{
    int rc;

    assert (_md_is_initialized);

    if (!x || !dst || !dstlenp) {
        return (-1);
    }
    rc = _md_final (x, dst, dstlenp);
    return (rc);
}


int
md_cleanup (md_ctx *x)
{
    int rc;

    assert (_md_is_initialized);

    if (!x) {
        return (-1);
    }
    rc = _md_cleanup (x);
    memset (x, 0, sizeof (*x));
    return (rc);
}


int
md_copy (md_ctx *xdst, md_ctx *xsrc)
{
    int rc;

    assert (_md_is_initialized);

    if (!xdst || !xsrc) {
        return (-1);
    }
    xdst->diglen = xsrc->diglen;
    rc = _md_copy (xdst, xsrc);
    return (rc);
}


int
md_size (munge_mac_t md)
{
    assert (_md_is_initialized);

    return (_md_size (md));
}


int
md_map_enum (munge_mac_t md, void *dst)
{
    assert (_md_is_initialized);

    return (_md_map_enum (md, dst));
}


/*****************************************************************************
 *  Private Functions (Libgcrypt)
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>
#include <string.h>
#include "log.h"

static int _md_map [MUNGE_MAC_LAST_ITEM];


static void
_md_init_subsystem (void)
{
    int i;

    for (i = 0; i < MUNGE_MAC_LAST_ITEM; i++) {
        _md_map [i] = -1;
    }
    _md_map [MUNGE_MAC_MD5] = GCRY_MD_MD5;
    _md_map [MUNGE_MAC_SHA1] = GCRY_MD_SHA1;
    _md_map [MUNGE_MAC_RIPEMD160] = GCRY_MD_RMD160;
    _md_map [MUNGE_MAC_SHA256] = GCRY_MD_SHA256;
    _md_map [MUNGE_MAC_SHA512] = GCRY_MD_SHA512;
    return;
}


static int
_md_init (md_ctx *x, munge_mac_t md)
{
    gcry_error_t e;
    int          algo;

    if (_md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    if ((e = gcry_md_open (&(x->ctx), algo, 0)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_open failed for MAC=%d: %s",
            md, gcry_strerror (e));
        return (-1);
    }
    x->diglen = gcry_md_get_algo_dlen (algo);
    return (0);
}


static int
_md_update (md_ctx *x, const void *src, int srclen)
{
    gcry_md_write (x->ctx, src, srclen);
    return (0);
}


static int
_md_final (md_ctx *x, void *dst, int *dstlenp)
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
_md_cleanup (md_ctx *x)
{
    gcry_md_close (x->ctx);
    return (0);
}


static int
_md_copy (md_ctx *xdst, md_ctx *xsrc)
{
    gcry_error_t e;

    if ((e = gcry_md_copy (&(xdst->ctx), xsrc->ctx)) != 0) {
        log_msg (LOG_DEBUG, "gcry_md_copy failed: %s", gcry_strerror (e));
        return (-1);
    }
    return (0);
}


static int
_md_size (munge_mac_t md)
{
    int algo;

    if (_md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    return (gcry_md_get_algo_dlen (algo));
}


static int
_md_map_enum (munge_mac_t md, void *dst)
{
    int algo = -1;

    if ((md > MUNGE_MAC_DEFAULT) && (md < MUNGE_MAC_LAST_ITEM)) {
        algo = _md_map [md];
    }
    if (algo < 0) {
        return (-1);
    }
    if (dst != NULL) {
        * (int *) dst = algo;
    }
    return (0);
}

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  Private Functions (OpenSSL)
 *****************************************************************************/

#if HAVE_OPENSSL

#include <openssl/evp.h>

static const EVP_MD * _md_map [MUNGE_MAC_LAST_ITEM];

static int _md_ctx_create (md_ctx *x);


static void
_md_init_subsystem (void)
{
    int i;

    for (i = 0; i < MUNGE_MAC_LAST_ITEM; i++) {
        _md_map [i] = NULL;
    }
    _md_map [MUNGE_MAC_MD5] = EVP_md5 ();
    _md_map [MUNGE_MAC_SHA1] = EVP_sha1 ();
    _md_map [MUNGE_MAC_RIPEMD160] = EVP_ripemd160 ();

#if HAVE_EVP_SHA256
    _md_map [MUNGE_MAC_SHA256] = EVP_sha256 ();
#endif /* HAVE_EVP_SHA256 */

#if HAVE_EVP_SHA512
    _md_map [MUNGE_MAC_SHA512] = EVP_sha512 ();
#endif /* HAVE_EVP_SHA512 */

    return;
}


static int
_md_init (md_ctx *x, munge_mac_t md)
{
    EVP_MD *algo;

    if (_md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    if (_md_ctx_create (x) < 0) {
        return (-1);
    }
#if HAVE_EVP_DIGESTINIT_EX
    /*  OpenSSL >= 0.9.7  */
    if (EVP_DigestInit_ex (x->ctx, algo, NULL) != 1) {
        return (-1);
    }
#elif HAVE_EVP_DIGESTINIT
    /*  EVP_DigestInit() implicitly initializes the EVP_MD_CTX.  */
    /*  OpenSSL < 0.9.7  */
    EVP_DigestInit (x->ctx, algo);
#else  /* !HAVE_EVP_DIGESTINIT */
#error "No OpenSSL EVP_DigestInit"
#endif /* !HAVE_EVP_DIGESTINIT */

    x->diglen = EVP_MD_size (algo);
    return (0);
}


static int
_md_ctx_create (md_ctx *x)
{
#if HAVE_EVP_MD_CTX_NEW
    /*  OpenSSL >= 1.1.0  */
    x->ctx = EVP_MD_CTX_new ();                         /* alloc & init */
#elif HAVE_EVP_MD_CTX_CREATE
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    x->ctx = EVP_MD_CTX_create ();                      /* alloc & init */
#else  /* !HAVE_EVP_MD_CTX_CREATE */
    x->ctx = OPENSSL_malloc (sizeof (EVP_MD_CTX));      /* allocate */
#if HAVE_EVP_MD_CTX_INIT
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    if (x->ctx != NULL ) {
        EVP_MD_CTX_init (x->ctx);                       /* initialize */
    }
#endif /* HAVE_EVP_MD_CTX_INIT */
#endif /* !HAVE_EVP_MD_CTX_CREATE */
    if (x->ctx == NULL) {
        return (-1);
    }
    return (0);
}


static int
_md_update (md_ctx *x, const void *src, int srclen)
{
#if HAVE_EVP_DIGESTUPDATE_RETURN_INT
    /*  OpenSSL >= 0.9.7  */
    if (EVP_DigestUpdate (x->ctx, src, (unsigned int) srclen) != 1) {
        return (-1);
    }
#elif HAVE_EVP_DIGESTUPDATE
    /*  OpenSSL < 0.9.7  */
    EVP_DigestUpdate (x->ctx, src, (unsigned int) srclen);
#else  /* !HAVE_EVP_DIGESTUPDATE */
#error "No OpenSSL EVP_DigestUpdate"
#endif /* !HAVE_EVP_DIGESTUPDATE */

    return (0);
}


static int
_md_final (md_ctx *x, void *dst, int *dstlenp)
{
    if (*dstlenp < x->diglen) {
        return (-1);
    }
#if HAVE_EVP_DIGESTFINAL_EX
    /*  OpenSSL >= 0.9.7  */
    if (!(EVP_DigestFinal_ex (x->ctx, dst, (unsigned int *) dstlenp))) {
        return (-1);
    }
#elif HAVE_EVP_DIGESTFINAL
    /*  OpenSSL < 0.9.7  */
    EVP_DigestFinal (x->ctx, dst, (unsigned int *) dstlenp);
#else  /* !HAVE_EVP_DIGESTFINAL */
#error "No OpenSSL EVP_DigestFinal"
#endif /* !HAVE_EVP_DIGESTFINAL */

    return (0);
}


static int
_md_cleanup (md_ctx *x)
{
    int rc = 0;

#if HAVE_EVP_MD_CTX_FREE
    /*  OpenSSL >= 1.1.0  */
    EVP_MD_CTX_free (x->ctx);
#elif HAVE_EVP_MD_CTX_DESTROY
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    EVP_MD_CTX_destroy (x->ctx);
#else  /* !HAVE_EVP_MD_CTX_DESTROY */
#if HAVE_EVP_MD_CTX_CLEANUP
    /*  OpenSSL >= 0.9.7, < 1.1.0  */
    if (EVP_MD_CTX_cleanup (x->ctx) != 1) {
        rc = -1;
    }
#endif /* HAVE_EVP_MD_CTX_CLEANUP */
    OPENSSL_free (x->ctx);
#endif /* !HAVE_EVP_MD_CTX_DESTROY */

    x->ctx = NULL;
    return (rc);
}


static int
_md_copy (md_ctx *xdst, md_ctx *xsrc)
{
    if (_md_ctx_create (xdst) < 0) {
        return (-1);
    }
#if HAVE_EVP_MD_CTX_COPY_EX
    /*  OpenSSL >= 0.9.7  */
    if (!(EVP_MD_CTX_copy_ex (xdst->ctx, xsrc->ctx))) {
        return (-1);
    }
#elif HAVE_EVP_MD_CTX_COPY
    /*  EVP_MD_CTX_copy() implicitly initializes the EVP_MD_CTX for xdst.  */
    if (!(EVP_MD_CTX_copy (xdst->ctx, xsrc->ctx))) {
        return (-1);
    }
#else  /* !HAVE_EVP_MD_CTX_COPY */
#error "No OpenSSL EVP_MD_CTX_copy"
#endif /* !HAVE_EVP_MD_CTX_COPY */

    return (0);
}


static int
_md_size (munge_mac_t md)
{
    EVP_MD *algo;

    if (_md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    return (EVP_MD_size (algo));
}


static int
_md_map_enum (munge_mac_t md, void *dst)
{
    const EVP_MD *algo = NULL;

    if ((md > MUNGE_MAC_DEFAULT) && (md < MUNGE_MAC_LAST_ITEM)) {
        algo = _md_map [md];
    }
    if (algo == NULL) {
        return (-1);
    }
    if (dst != NULL) {
        * (const EVP_MD **) dst = algo;
    }
    return (0);
}

#endif /* HAVE_OPENSSL */
