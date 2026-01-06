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


#ifndef MD_H
#define MD_H


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
} md_ctx;

#endif /* HAVE_LIBGCRYPT */


#if HAVE_OPENSSL

#include <openssl/evp.h>

typedef struct {
    EVP_MD_CTX         *ctx;
    int                 diglen;
} md_ctx;

#endif /* HAVE_OPENSSL */


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

void md_init_subsystem (void);

int md_init (md_ctx *x, munge_mac_t md);

int md_update (md_ctx *x, const void *src, int srclen);

int md_final (md_ctx *x, void *dst, int *dstlenp);

int md_cleanup (md_ctx *x);

int md_copy (md_ctx *xdst, md_ctx *xsrc);

int md_size (munge_mac_t md);

int md_map_enum (munge_mac_t md, void *dst);


#endif /* !MD_H */
