/*****************************************************************************
 *  Copyright (C) 2007-2026 Lawrence Livermore National Security, LLC.
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
 *  <https://www.gnu.org/licenses/>.
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

int mac_update (mac_ctx *x, const void *src, int srclen);

int mac_final (mac_ctx *x, void *dst, int *dstlenp);

int mac_cleanup (mac_ctx *x);

int mac_size (munge_mac_t md);

int mac_block (munge_mac_t md, const void *key, int keylen,
               void *dst, int *dstlenp, const void *src, int srclen);

int mac_map_enum (munge_mac_t md, void *dst);


#endif /* !MAC_H */
