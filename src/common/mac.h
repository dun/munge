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
} mac_ctx;

#endif /* HAVE_LIBGCRYPT */


#if HAVE_OPENSSL

#include <openssl/evp.h>

/*  openSUSE 15.1 has OpenSSL 1.1.0i-fips (14 Aug 2018) but defines EVP_MAC_CTX
 *    in <openssl/ossl_typ.h> (libopenssl-1_1-devel-1.1.0i-lp151.8.12.2.x86_64)
 *    (EVP_MAC_CTX shouldn't appear until OpenSSL 3.0), so also add a guard for
 *    HAVE_EVP_MAC_CTX_NEW to prevent EVP_MAC_CTX from being erroneously used.
 */
#if HAVE_EVP_MAC_CTX_P && HAVE_EVP_MAC_CTX_NEW

/*  OpenSSL >= 3.0  */
typedef struct {
    EVP_MAC_CTX        *ctx;
    int                 diglen;
} mac_ctx;

#else  /* !HAVE_EVP_MAC_CTX_P */

#if HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>
#endif /* HAVE_OPENSSL_HMAC_H */

/*  OpenSSL < 3.0  */
typedef struct {
    HMAC_CTX           *ctx;
    int                 diglen;
} mac_ctx;

#endif /* !HAVE_EVP_MAC_CTX_P */

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

int mac_final (mac_ctx *x, void *dst, int *dstlenp);
/*
 *  Finalizes the MAC context [x], placing the MAC in [dst] of length
 *    [dstlenp].  The [dst] buffer must have sufficient space for the MAC
 *    output (mac_size).
 *  After this function, no further calls to md_update() should be made.
 *  Returns 0 on success, or -1 on error; in addition, [dstlenp] will be set
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
               void *dst, int *dstlenp, const void *src, int srclen);
/*
 *  Computes the MAC without the need of a context; this requires
 *    the [src] to be contiguous.
 *  Uses the message digest [md] and key [key] of [keylen] bytes.
 *  Reads [srclen] bytes of data from [src], and writes the MAC to [dst]
 *    of length [dstlenp].
 *  Returns 0 on success, or -1 on error; in addition, [dstlenp] will be set
 *    to the number of bytes written to [dst].
 */

int mac_map_enum (munge_mac_t md, void *dst);
/*
 *  Map the specified [md] algorithm to the internal representation used
 *    by the underlying cryptographic library.
 *  If [dst] is non-NULL, write the cryptographic library's internal
 *    representation of the message digest algorithm to [dst]; otherwise, just
 *    validate the specified [md] algorithm.
 *  Returns 0 on success, or -1 on error.
 */


#endif /* !MAC_H */
