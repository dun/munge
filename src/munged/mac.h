/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2003-2006 The Regents of the University of California.
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


#ifndef MAC_H
#define MAC_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <openssl/evp.h>
#include <openssl/hmac.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct {
    HMAC_CTX            ctx;
#ifndef NDEBUG
    int                 magic;
    int                 finalized;
#endif /* !NDEBUG */
} mac_ctx;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

int mac_init (mac_ctx *x, const EVP_MD *md,
              const void *key, int keylen);
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
 *  Finalizes the MAC context [x], placing the MAC in [dst] which must
 *    have sufficient space for the message digest output (mac_size).
 *    If [dstlen] is not NULL, it will be set to the output size.
 *  After this function, no further calls to mac_update() should be made.
 *  Returns 0 on success, or -1 on error.
 */

int mac_cleanup (mac_ctx *x);
/*
 *  Clears the MAC context [x].
 *  Returns 0 on success, or -1 on error.
 */

int mac_size (const EVP_MD *md);
/*
 *  Returns the size (in bytes) of the message digest [md].
 */

int mac_block (const EVP_MD *md, const void *key, int keylen,
               void *dst, int *dstlen, const void *src, int srclen);
/*
 *  Computes the MAC without the need of a context; this requires
 *    the [src] to be contiguous.
 *  Uses the message digest [md] and key [key] of [keylen] bytes.
 *  Reads [srclen] bytes of data from [src], and writes the MAC to [dst].
 *    If [dstlen] is not NULL, it will be set to the output size.
 *  Returns 0 on success, or -1 on error.
 */


#endif /* !MAC_H */
