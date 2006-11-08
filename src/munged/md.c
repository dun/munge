/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory.
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
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
 *  Private Prototypes
 *****************************************************************************/

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

int
md_init (md_ctx *x, munge_mac_t md)
{
    int rc;

    assert (x != NULL);

    rc = _md_init (x, md);
    assert (x->magic = MD_MAGIC);
    assert (!(x->finalized = 0));
    return (rc);
}


int
md_update (md_ctx *x, const void *src, int srclen)
{
    int rc;

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

    assert (x != NULL);
    assert (x->magic == MD_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);
    assert (dstlen != NULL);

    rc = _md_final (x, dst, dstlen);
    assert (x->finalized = 1);
    return (rc);
}


int
md_cleanup (md_ctx *x)
{
    int rc;

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

    assert (xdst != NULL);
    assert (xsrc != NULL);
    assert (xsrc->magic == MD_MAGIC);
    assert (xsrc->finalized != 1);

    rc = _md_copy (xdst, xsrc);
    assert (!(xdst->finalized = 0));
    assert (xdst->magic = MD_MAGIC);
    return (rc);
}


int
md_size (munge_mac_t md)
{
    return (_md_size (md));
}


int
md_map_enum (munge_mac_t md, void *dst)
{
    return (_md_map_enum (md, dst));
}


/*****************************************************************************
 *  Private Functions (Libgcrypt)
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>
#include <string.h>

static int
_md_init (md_ctx *x, munge_mac_t md)
{
    int algo;

    if (_md_map_enum (md, &algo) < 0) {
        return (-1);
    }
    if (gcry_md_open (&(x->ctx), algo, 0) != 0) {
        return (-1);
    }
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
    int            algo;
    int            len;

    if ((digest = gcry_md_read (x->ctx, 0)) == NULL) {
        return (-1);
    }
    algo = gcry_md_get_algo (x->ctx);
    len = gcry_md_get_algo_dlen (algo);
    if (len > *dstlen) {
        return (-1);
    }
    memcpy (dst, digest, len);
    *dstlen = len;
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
    if (gcry_md_copy (&(xdst->ctx), xsrc->ctx) != 0) {
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
    int algo;
    int rc = 0;

    switch (md) {
        case MUNGE_MAC_MD5:
            algo = GCRY_MD_MD5;
            break;
        case MUNGE_MAC_SHA1:
            algo = GCRY_MD_SHA1;
            break;
        case MUNGE_MAC_RIPEMD160:
            algo = GCRY_MD_RMD160;
            break;
        case MUNGE_MAC_SHA256:
            algo = GCRY_MD_SHA256;
            break;
        default:
            rc = -1;
            break;
    }
    if ((dst != NULL) && (rc == 0)) {
        * (int *) dst = algo;
    }
    return (rc);
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
    return (0);
}


static int
_md_update (md_ctx *x, const void *src, int srclen)
{
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
    EVP_MD *algo;
    int     rc = 0;

    switch (md) {
        case MUNGE_MAC_MD5:
            algo = EVP_md5 ();
            break;
        case MUNGE_MAC_SHA1:
            algo = EVP_sha1 ();
            break;
        case MUNGE_MAC_RIPEMD160:
            algo = EVP_ripemd160 ();
            break;
#if HAVE_EVP_SHA256
        case MUNGE_MAC_SHA256:
            algo = EVP_sha256 ();
            break;
#endif /* HAVE_EVP_SHA256 */
        default:
            rc = -1;
            break;
    }
    if ((dst != NULL) && (rc == 0)) {
        * (EVP_MD **) dst = algo;
    }
    return (rc);
}

#endif /* HAVE_OPENSSL */
