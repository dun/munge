/*****************************************************************************
 *  $Id: cipher.c,v 1.3 2004/02/05 21:36:03 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include "cipher.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  EVP_CipherInit() implicitly initializes the EVP_CIPHER_CTX.
 *    This call has been deprecated as of OpenSSL 0.9.7.
 *  EVP_CipherInit(), EVP_CipherUpdate(), and EVP_CIPHER_CTX_cleanup()
 *    return void in OpenSSL 0.9.5a and earlier versions, and int in later
 *    versions.  I'm using EVP_CipherInit_ex() as my test for this behavior.
 *    This probably isn't the best test since it fails for OpenSSL 0.9.6b.
 *    But this isn't as bad as it sounds since software versions of these
 *    functions will never return errors (unless there is a programming error),
 *    and hardware versions require the EVP_CipherInit_ex() interface provided
 *    by OpenSSL 0.9.7.
 *  If EVP_CipherInit_ex() exists, so should EVP_CIPHER_CTX_init().
 *    But EVP_CIPHER_CTX_cleanup() exists in the versions of which I'm aware.
 */

/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define CIPHER_MAGIC 0xDEADACE1


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
cipher_init (cipher_ctx *x, const EVP_CIPHER *ci,
             unsigned char *key, unsigned char *iv, int enc)
{
    assert (x != NULL);
    assert (ci != NULL);
    assert (key != NULL);
    assert (iv != NULL);
    assert ((enc == 0) || (enc == 1));

#if HAVE_EVP_CIPHERINIT_EX
    EVP_CIPHER_CTX_init (&(x->ctx));
    if (!(EVP_CipherInit_ex (&(x->ctx), ci, NULL, key, iv, enc)))
        return (-1);
#else  /* !HAVE_EVP_CIPHERINIT_EX */
    EVP_CipherInit (&(x->ctx), ci, key, iv, enc);
#endif /* !HAVE_EVP_CIPHERINIT_EX */
    assert (x->magic = CIPHER_MAGIC);
    assert (!(x->finalized = 0));
    return (0);
}


int
cipher_update (cipher_ctx *x, void *dst, int *dstlen,
               const void *src, int srclen)
{
    assert (x != NULL);
    assert (x->magic == CIPHER_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);
    assert (src != NULL);

#if HAVE_EVP_CIPHERINIT_EX
    if (!(EVP_CipherUpdate (&(x->ctx), dst, dstlen, (void *) src, srclen)))
        return (-1);
#else  /* !HAVE_EVP_CIPHERINIT_EX */
    EVP_CipherUpdate (&(x->ctx), dst, dstlen, (void *) src, srclen);
#endif /* !HAVE_EVP_CIPHERINIT_EX */
    return (0);
}


int
cipher_final (cipher_ctx *x, void *dst, int *dstlen)
{
    assert (x != NULL);
    assert (x->magic == CIPHER_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);

#if HAVE_EVP_CIPHERINIT_EX
    if (!(EVP_CipherFinal_ex (&(x->ctx), dst, dstlen)))
        return (-1);
#else  /* !HAVE_EVP_CIPHERINIT_EX */
    if (!(EVP_CipherFinal (&(x->ctx), dst, dstlen)))
        return (-1);
#endif /* !HAVE_EVP_CIPHERINIT_EX */
    assert (x->finalized = 1);
    return (0);
}


int
cipher_cleanup (cipher_ctx *x)
{
    int rc = 0;

    assert (x != NULL);
    assert (x->magic == CIPHER_MAGIC);

#if HAVE_EVP_CIPHERINIT_EX
    if (!(EVP_CIPHER_CTX_cleanup (&(x->ctx))))
        rc = -1;
#else  /* !HAVE_EVP_CIPHERINIT_EX */
    EVP_CIPHER_CTX_cleanup (&(x->ctx));
#endif /* !HAVE_EVP_CIPHERINIT_EX */
    memset (x, 0, sizeof (*x));
    assert (x->magic = ~CIPHER_MAGIC);
    return (rc);
}


int
cipher_block_size (const EVP_CIPHER *ci)
{
    return ((ci == NULL) ? 0 : EVP_CIPHER_block_size (ci));
}


int
cipher_iv_size (const EVP_CIPHER *ci)
{
    return ((ci == NULL) ? 0 : EVP_CIPHER_iv_length (ci));
}


int
cipher_key_size (const EVP_CIPHER *ci)
{
    return ((ci == NULL) ? 0 : EVP_CIPHER_key_length (ci));
}
