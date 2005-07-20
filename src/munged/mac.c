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
#include <openssl/hmac.h>
#include "mac.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  HMAC_Init() implicitly initializes the HMAC_CTX.
 *    This call has been deprecated as of OpenSSL 0.9.7.
 *  If HMAC_Init_ex() exists, so should
 *    HMAC_CTX_init() & HMAC_CTX_cleanup().
 */

/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MAC_MAGIC 0xDEADACE2


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
mac_init (mac_ctx *x, const EVP_MD *md, const void *key, int keylen)
{
    assert (x != NULL);
    assert (md != NULL);
    assert (key != NULL);

#if HAVE_HMAC_INIT_EX
    HMAC_CTX_init (&(x->ctx));
    HMAC_Init_ex (&(x->ctx), key, keylen, md, NULL);
#else  /* !HAVE_HMAC_INIT_EX */
    HMAC_Init (&(x->ctx), key, keylen, md);
#endif /* !HAVE_HMAC_INIT_EX */
    assert (x->magic = MAC_MAGIC);
    assert (!(x->finalized = 0));
    return (0);
}


int
mac_update (mac_ctx *x, const void *src, int srclen)
{
    assert (x != NULL);
    assert (x->magic == MAC_MAGIC);
    assert (x->finalized != 1);
    assert (src != NULL);

    HMAC_Update (&(x->ctx), src, srclen);
    return (0);
}


int
mac_final (mac_ctx *x, void *dst, int *dstlen)
{
    assert (x != NULL);
    assert (x->magic == MAC_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);

    HMAC_Final (&(x->ctx), dst, (unsigned int *) dstlen);
    assert (x->finalized = 1);
    return (0);
}


int
mac_cleanup (mac_ctx *x)
{
    assert (x != NULL);
    assert (x->magic == MAC_MAGIC);

#if HAVE_HMAC_INIT_EX
    HMAC_CTX_cleanup (&(x->ctx));
#else  /* !HAVE_HMAC_INIT_EX */
    HMAC_cleanup (&(x->ctx));
#endif /* !HAVE_HMAC_INIT_EX */
    memset (x, 0, sizeof (*x));
    assert (x->magic = ~MAC_MAGIC);
    return (0);
}


int
mac_size (const EVP_MD *md)
{
    return ((md == NULL) ? 0 : EVP_MD_size (md));
}


int
mac_block (const EVP_MD *md, const void *key, int keylen,
           void *dst, int *dstlen, const void *src, int srclen)
{
    assert (md != NULL);
    assert (key != NULL);
    assert (src != NULL);
    assert (dst != NULL);

    HMAC (md, key, keylen, src, srclen, dst, (unsigned int *) dstlen);

    return (0);
}
