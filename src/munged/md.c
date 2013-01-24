/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2013 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://munge.googlecode.com/>.
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
 *  Constants
 *****************************************************************************/

#define MD_MAGIC 0xDEADACE3


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
static int _md_final (md_ctx *x, void *dst, int *dstlen);
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
    assert (x != NULL);

    rc = _md_init (x, md);
    if (rc >= 0) {
        assert (x->magic = MD_MAGIC);
        assert (!(x->finalized = 0));
    }
    return (rc);
}


int
md_update (md_ctx *x, const void *src, int srclen)
{
    int rc;

    assert (_md_is_initialized);
    assert (x != NULL);
    assert (x->magic == MD_MAGIC);
    assert (x->finalized != 1);
    assert (src != NULL);

    if (srclen <= 0) {
        return (0);
    }
    rc = _md_update (x, src, srclen);
    return (rc);
}


int
md_final (md_ctx *x, void *dst, int *dstlen)
{
    int rc;

    assert (_md_is_initialized);
    assert (x != NULL);
    assert (x->magic == MD_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);
    assert (dstlen != NULL);

    if ((dstlen == NULL) || (*dstlen <= 0)) {
        return (-1);
    }
    rc = _md_final (x, dst, dstlen);
    assert (x->finalized = 1);
    return (rc);
}


int
md_cleanup (md_ctx *x)
{
    int rc;

    assert (_md_is_initialized);
    assert (x != NULL);
    assert (x->magic == MD_MAGIC);

    rc = _md_cleanup (x);
    memset (x, 0, sizeof (*x));
    assert (x->magic = ~MD_MAGIC);
    return (rc);
}


int
md_copy (md_ctx *xdst, md_ctx *xsrc)
{
    int rc;

    assert (_md_is_initialized);
    assert (xdst != NULL);
    assert (xsrc != NULL);
    assert (xsrc->magic == MD_MAGIC);
    assert (xsrc->finalized != 1);

    xdst->diglen = xsrc->diglen;
    rc = _md_copy (xdst, xsrc);
    assert (!(xdst->finalized = 0));
    assert (xdst->magic = MD_MAGIC);
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
_md_final (md_ctx *x, void *dst, int *dstlen)
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
/*
 *  EVP_DigestInit() & EVP_DigestCopy() implicitly initialize the EVP_MD_CTX.
 *    These calls have been deprecated as of OpenSSL 0.9.7.
 *  EVP_DigestUpdate() returns void in versions prior to OpenSSL 0.9.7.
 *    I'm using EVP_DigestInit_ex() as my test for this behavior.
 *  If EVP_DigestInit_ex() exists, so should
 *    EVP_MD_CTX_init() & EVP_MD_CTX_cleanup().
 */

#if HAVE_OPENSSL

#include <openssl/evp.h>

static const EVP_MD * _md_map [MUNGE_MAC_LAST_ITEM];


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
#if HAVE_EVP_DIGESTINIT_EX
    EVP_MD_CTX_init (&(x->ctx));
    if (!(EVP_DigestInit_ex (&(x->ctx), algo, NULL))) {
        return (-1);
    }
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    EVP_DigestInit (&(x->ctx), algo);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    x->diglen = EVP_MD_size (algo);
    return (0);
}


static int
_md_update (md_ctx *x, const void *src, int srclen)
{
/*  Since [srclen] will always be positive due to the check in md_update(),
 *    the cast to unsigned int is safe.
 */
#if HAVE_EVP_DIGESTINIT_EX
    if (!(EVP_DigestUpdate (&(x->ctx), src, (unsigned int) srclen))) {
        return (-1);
    }
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    EVP_DigestUpdate (&(x->ctx), src, (unsigned int) srclen);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    return (0);
}


static int
_md_final (md_ctx *x, void *dst, int *dstlen)
{
    if (*dstlen < x->diglen) {
        return (-1);
    }
#if HAVE_EVP_DIGESTINIT_EX
    if (!(EVP_DigestFinal_ex (&(x->ctx), dst, (unsigned int *) dstlen))) {
        return (-1);
    }
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    EVP_DigestFinal (&(x->ctx), dst, (unsigned int *) dstlen);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    return (0);
}


static int
_md_cleanup (md_ctx *x)
{
#if HAVE_EVP_DIGESTINIT_EX
    if (!(EVP_MD_CTX_cleanup (&(x->ctx)))) {
        return (-1);
    }
#endif /* HAVE_EVP_DIGESTINIT_EX */
    return (0);
}


static int
_md_copy (md_ctx *xdst, md_ctx *xsrc)
{
#if HAVE_EVP_DIGESTINIT_EX
    EVP_MD_CTX_init (&(xdst->ctx));
    if (!(EVP_MD_CTX_copy_ex (&(xdst->ctx), &(xsrc->ctx)))) {
        return (-1);
    }
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    if (!(EVP_MD_CTX_copy (&(xdst->ctx), &(xsrc->ctx)))) {
        return (-1);
    }
#endif /* !HAVE_EVP_DIGESTINIT_EX */
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
