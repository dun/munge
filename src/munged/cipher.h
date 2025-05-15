/*****************************************************************************
 *  Copyright (C) 2007-2025 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
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

int cipher_init (cipher_ctx *x, munge_cipher_t cipher,
                 unsigned char *key, unsigned char *iv, int enc);

int cipher_update (cipher_ctx *x, void *dst, int *dstlenp,
                   const void *src, int srclen);

int cipher_final (cipher_ctx *x, void *dst, int *dstlenp);

int cipher_cleanup (cipher_ctx *x);

int cipher_block_size (munge_cipher_t cipher);

int cipher_iv_size (munge_cipher_t cipher);

int cipher_key_size (munge_cipher_t cipher);

int cipher_map_enum (munge_cipher_t cipher, void *dst);


#endif /* !CIPHER_H */
