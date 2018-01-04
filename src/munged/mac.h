/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2018 Lawrence Livermore National Security, LLC.
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


#ifndef MAC_H
#define MAC_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <munge.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

typedef struct {
    gcry_md_hd_t        ctx;
    int                 diglen;
#ifndef NDEBUG
    int                 magic;
    int                 finalized;
#endif /* !NDEBUG */
} mac_ctx;

#endif /* HAVE_LIBGCRYPT */


#if HAVE_OPENSSL

#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct {
    HMAC_CTX           *ctx;
    int                 diglen;
#ifndef NDEBUG
    int                 magic;
    int                 finalized;
#endif /* !NDEBUG */
} mac_ctx;

#endif /* HAVE_OPENSSL */


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

int mac_init (mac_ctx *x, munge_mac_t md, const void *key, int keylen);
/*
 *  Initializes the message authentication code (MAC) context [x]
 *    with the message digest [md] and key [key] of [keylen] bytes.
 *  Returns 0 on success, or -1 on error.
 */

int mac_update (mac_ctx *x, const void *src, int srclen);
/*
 *  Updates the MAC context [x], reading [srclen] bytes from [src].
 *    This can be called multiple times to process successive blocks of data.
 *  Returns 0 on success, or -1 on error.
 */

int mac_final (mac_ctx *x, void *dst, int *dstlen);
/*
 *  Finalizes the MAC context [x], placing the MAC in [dst] of length [dstlen].
 *    The [dst] buffer must have sufficient space for the MAC output
 *    (mac_size).
 *  After this function, no further calls to md_update() should be made.
 *  Returns 0 on success, or -1 on error; in addition, [dstlen] will be set
 *    to the number of bytes written to [dst].
 */

int mac_cleanup (mac_ctx *x);
/*
 *  Clears the MAC context [x].
 *  Returns 0 on success, or -1 on error.
 */

int mac_size (munge_mac_t md);
/*
 *  Returns the size (in bytes) of the message digest [md], or -1 on error.
 */

int mac_block (munge_mac_t md, const void *key, int keylen,
               void *dst, int *dstlen, const void *src, int srclen);
/*
 *  Computes the MAC without the need of a context; this requires
 *    the [src] to be contiguous.
 *  Uses the message digest [md] and key [key] of [keylen] bytes.
 *  Reads [srclen] bytes of data from [src], and writes the MAC to [dst]
 *    of length [dstlen].
 *  Returns 0 on success, or -1 on error; in addition, [dstlen] will be set
 *    to the number of bytes written to [dst].
 */

int mac_map_enum (munge_mac_t mac, void *dst);
/*
 *  Map the specified [mac] algorithm to the internal representation used
 *    by the underlying cryptographic library.
 *  If [dst] is non-NULL, write the cryptographic library's internal
 *    representation of the message digest algorithm to [dst].
 *  Returns 0 on success, or -1 on error.
 */


#endif /* !MAC_H */
