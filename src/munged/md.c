/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2005 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
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
#include <string.h>
#include <openssl/evp.h>
#include "md.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  EVP_DigestInit() & EVP_DigestCopy() implicitly initialize the EVP_MD_CTX.
 *    These calls have been deprecated as of OpenSSL 0.9.7.
 *  EVP_DigestUpdate() returns void in versions prior to OpenSSL 0.9.7.
 *    I'm using EVP_DigestInit_ex() as my test for this behavior.
 *  If EVP_DigestInit_ex() exists, so should
 *    EVP_MD_CTX_init() & EVP_MD_CTX_cleanup().
 */

/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MD_MAGIC 0xDEADACE3


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
md_init (md_ctx *x, const EVP_MD *md)
{
    assert (x != NULL);
    assert (md != NULL);

#if HAVE_EVP_DIGESTINIT_EX
    EVP_MD_CTX_init (&(x->ctx));
    if (!(EVP_DigestInit_ex (&(x->ctx), md, NULL)))
        return (-1);
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    EVP_DigestInit (&(x->ctx), md);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    assert (x->magic = MD_MAGIC);
    assert (!(x->finalized = 0));
    return (0);
}


int
md_update (md_ctx *x, const void *src, int srclen)
{
    assert (x != NULL);
    assert (x->magic == MD_MAGIC);
    assert (x->finalized != 1);
    assert (src != NULL);

#if HAVE_EVP_DIGESTINIT_EX
    if (!(EVP_DigestUpdate (&(x->ctx), src, (unsigned int) srclen)))
        return (-1);
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    EVP_DigestUpdate (&(x->ctx), src, (unsigned int) srclen);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    return (0);
}


int
md_final (md_ctx *x, void *dst, int *dstlen)
{
    assert (x != NULL);
    assert (x->magic == MD_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);

#if HAVE_EVP_DIGESTINIT_EX
    if (!(EVP_DigestFinal_ex (&(x->ctx), dst, (unsigned int *) dstlen)))
        return (-1);
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    EVP_DigestFinal (&(x->ctx), dst, (unsigned int *) dstlen);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    assert (x->finalized = 1);
    return (0);
}


int
md_cleanup (md_ctx *x)
{
    int rc = 0;

    assert (x != NULL);
    assert (x->magic == MD_MAGIC);

#if HAVE_EVP_DIGESTINIT_EX
    if (!(EVP_MD_CTX_cleanup (&(x->ctx))))
        rc = -1;
#endif /* HAVE_EVP_DIGESTINIT_EX */
    memset (x, 0, sizeof (*x));
    assert (x->magic = ~MD_MAGIC);
    return (rc);
}


int
md_copy (md_ctx *xdst, md_ctx *xsrc)
{
    assert (xdst != NULL);
    assert (xsrc != NULL);
    assert (xsrc->magic == MD_MAGIC);
    assert (xsrc->finalized != 1);

#if HAVE_EVP_DIGESTINIT_EX
    EVP_MD_CTX_init (&(xdst->ctx));
    if (!(EVP_MD_CTX_copy_ex (&(xdst->ctx), &(xsrc->ctx))))
        return (-1);
#else  /* !HAVE_EVP_DIGESTINIT_EX */
    if (!(EVP_MD_CTX_copy (&(xdst->ctx), &(xsrc->ctx))))
        return (-1);
#endif /* !HAVE_EVP_DIGESTINIT_EX */
    assert (!(xdst->finalized = 0));
    assert (xdst->magic = MD_MAGIC);
    return (0);
}


int
md_size (const EVP_MD *md)
{
    return ((md == NULL) ? 0 : EVP_MD_size (md));
}
