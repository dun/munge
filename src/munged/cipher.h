/*****************************************************************************
 *  $Id: cipher.h,v 1.1 2003/04/08 18:16:16 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
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


#ifndef CIPHER_H
#define CIPHER_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <openssl/evp.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct {
    EVP_CIPHER_CTX      ctx;
#ifndef NDEBUG
    int                 magic;
    int                 finalized;
#endif /* !NDEBUG */
} cipher_ctx;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

int cipher_init (cipher_ctx *x, const EVP_CIPHER *ci,
                 unsigned char *key, unsigned char *iv, int enc);
/*
 *  Initializes the cipher context [x] with the cipher [ci],
 *    symmetric key [key], and initialization vector [iv].
 *  The [enc] parm is set to 1 for encryption, and 0 for decryption.
 *  Returns 0 on success, or -1 on error.
 */

int cipher_update (cipher_ctx *x, void *dst, unsigned int *dstlen,
                   const void *src, unsigned int srclen);
/*
 *  Updates the cipher context [x], reading [srclen] bytes from [src] and
 *    writing [dstlen] bytes to [dst].  This can be called multiple times
 *    to process successive blocks of data.
 *  The number of bytes written will be from 0 to (srclen + cipher_block_size)
 *    depending on the cipher block alignment.
 *  Returns 0 on success, or -1 on error.
 */

int cipher_final (cipher_ctx *x, void *dst, unsigned int *dstlen);
/*
 *  Finalizes the cipher context [x], processing the "final" data
 *    remaining in a partial block and writing [dstlen] bytes to [dst].
 *  The number of bytes written will be at most cipher_block_size() bytes
 *    depending on the cipher block alignment.
 *  After this function, no further calls to cipher_update() should be made.
 *  Returns 0 on success, or -1 on error.
 */

int cipher_cleanup (cipher_ctx *x);
/*
 *  Clears the cipher context [x].
 *  Returns 0 on success, or -1 on error.
 */

int cipher_block_size (const EVP_CIPHER *ci);
/*
 *  Returns the block size (in bytes) of the cipher [ci].
 */

int cipher_iv_size (const EVP_CIPHER *ci);
/*
 *  Returns the initialization vector length (in bytes) of the cipher [ci],
 *    or 0 if the cipher does not use an IV.
 */

int cipher_key_size (const EVP_CIPHER *ci);
/*
 *  Returns the key length (in bytes) of the cipher [ci].
 */


#endif /* !CIPHER_H */
