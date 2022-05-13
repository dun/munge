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


#ifndef CIPHER_H
#define CIPHER_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <munge.h>
#include "munge_defs.h"


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

typedef struct {
    gcry_cipher_hd_t    ctx;
    int                 do_encrypt;
    int                 len;
    int                 blklen;
    unsigned char       buf [MUNGE_MAXIMUM_BLK_LEN];
} cipher_ctx;

#endif /* HAVE_LIBGCRYPT */


#if HAVE_OPENSSL

#include <openssl/evp.h>

typedef struct {
    EVP_CIPHER_CTX     *ctx;
} cipher_ctx;

#endif /* HAVE_OPENSSL */


enum {
    CIPHER_DECRYPT = 0,
    CIPHER_ENCRYPT = 1
};


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

void cipher_init_subsystem (void);
/*
 *  Initializes the cipher subsystem.
 *  WARNING: This routine is *NOT* guaranteed to be thread-safe.
 */

int cipher_init (cipher_ctx *x, munge_cipher_t cipher,
                 unsigned char *key, unsigned char *iv, int enc);
/*
 *  Initializes the cipher context [x] with cipher [cipher],
 *    symmetric key [key], and initialization vector [iv].
 *  The [enc] parm is set to 1 for encryption, and 0 for decryption.
 *  Returns 0 on success, or -1 on error.
 */

int cipher_update (cipher_ctx *x, void *dst, int *dstlenp,
                   const void *src, int srclen);
/*
 *  Updates the cipher context [x], reading [srclen] bytes from [src] and
 *    writing the result into [dst] of length [dstlenp].  This can be called
 *    multiple times to process successive blocks of data.
 *  The number of bytes written will be from 0 to (srclen + cipher_block_size)
 *    depending on the cipher block alignment.
 *  Returns 0 on success, or -1 on error; in addition, [dstlenp] will be set
 *    to the number of bytes written to [dst].
 */

int cipher_final (cipher_ctx *x, void *dst, int *dstlenp);
/*
 *  Finalizes the cipher context [x], processing the "final" data
 *    remaining in a partial block and writing the result into [dst] of
 *    length [dstlen].
 *  The number of bytes written will be at most cipher_block_size() bytes
 *    depending on the cipher block alignment.
 *  After this function, no further calls to cipher_update() should be made.
 *  Returns 0 on success, or -1 on error; in addition, [dstlenp] will be set
 *    to the number of bytes written to [dst].
 */

int cipher_cleanup (cipher_ctx *x);
/*
 *  Clears the cipher context [x].
 *  Returns 0 on success, or -1 on error.
 */

int cipher_block_size (munge_cipher_t cipher);
/*
 *  Returns the block size (in bytes) of the cipher [cipher], or -1 on error.
 */

int cipher_iv_size (munge_cipher_t cipher);
/*
 *  Returns the initialization vector length (in bytes) of the cipher [cipher],
 *    0 if the cipher does not use an IV, or -1 on error.
 */

int cipher_key_size (munge_cipher_t cipher);
/*
 *  Returns the key length (in bytes) of the cipher [cipher], or -1 on error.
 */

int cipher_map_enum (munge_cipher_t cipher, void *dst);
/*
 *  Map the specified [cipher] algorithm to the internal representation used
 *    by the underlying cryptographic library.
 *  If [dst] is non-NULL, write the cryptographic library's internal
 *    representation of the cipher algorithm to [dst]; otherwise, just validate
 *    the specified [cipher] algorithm.
 *  Returns 0 on success, or -1 on error.
 */


#endif /* !CIPHER_H */
