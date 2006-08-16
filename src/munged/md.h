/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2006 The Regents of the University of California.
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


#ifndef MD_H
#define MD_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <openssl/evp.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct {
    EVP_MD_CTX          ctx;
#ifndef NDEBUG
    int                 magic;
    int                 finalized;
#endif /* !NDEBUG */
} md_ctx;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

int md_init (md_ctx *x, const EVP_MD *md);
/*
 *  Initializes the message digest context [x] with the message digest [md].
 *  Returns 0 on success, or -1 on error.
 */

int md_update (md_ctx *x, const void *src, int srclen);
/*
 *  Updates the message digest context [x], reading [srclen] bytes from [src].
 *    This can be called multiple times to process successive blocks of data.
 *  Returns 0 on success, or -1 on error.
 */

int md_final (md_ctx *x, void *dst, int *dstlen);
/*
 *  Finalizes the message digest context [x], placing the MAC in [dst] which
 *    must have sufficient space for the message digest output (md_size).
 *    If [dstlen] is not NULL, it will be set to the output size.
 *  After this function, no further calls to md_update() should be made.
 *  Returns 0 on success, or -1 on error.
 */

int md_cleanup (md_ctx *x);
/*
 *  Clears the message digest context [x].
 *  Returns 0 on success, or -1 on error.
 */

int md_copy (md_ctx *xdst, md_ctx *xsrc);
/*
 *  Copies the message digest state from the [xsrc] context to [xdst].
 *    This is useful if large amounts of data are to be hashed which only
 *    differ in thye last few bytes.
 *  Returns 0 on success, or -1 on error.
 */

int md_size (const EVP_MD *md);
/*
 *  Returns the size (in bytes) of the message digest [md].
 */


#endif /* !MD_H */
