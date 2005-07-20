/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2005 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
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


#ifndef BASE64_H
#define BASE64_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct {
    unsigned char       buf[3];
    int                 num;
    int                 pad;
#ifndef NDEBUG
    int                 magic;
    int                 finalized;
#endif /* !NDEBUG */
} base64_ctx;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

int base64_init (base64_ctx *x);
/*
 *  Initializes the base64 context [x] for base64 encoding/decoding of data.
 *  Returns 0 on success, or -1 on error.
 */

int base64_encode_update (base64_ctx *x, void *dst, int *dstlen,
                          const void *src, int srclen);
/*
 *  Updates the base64 context [x], encoding [srclen] bytes from [src]
 *    into [dst], and setting [dstlen] to the number of bytes written.
 *  This can be called multiple times to process successive blocks of data.
 *  Returns 0 on success, or -1 on error.
 */

int base64_encode_final (base64_ctx *x, void *dst, int *dstlen);
/*
 *  Finalizes the base64 context [x], encoding the "final" data remaining
 *    in a partial block into [dst], and setting [dstlen] to the number of
 *    bytes written.
 *  After calling this function, no further updates should be made to [x]
 *    without re-initializing it first.
 *  Returns 0 on success, or -1 on error.
 */

int base64_decode_update (base64_ctx *x, void *dst, int *dstlen,
                          const void *src, int srclen);
/*
 *  Updates the base64 context [x], decoding [srclen] bytes from [src]
 *    into [dst], and setting [dstlen] to the number of bytes written.
 *  This can be called multiple times to process successive blocks of data.
 *  Returns 0 on success, or -1 on error.
 */

int base64_decode_final (base64_ctx *x, void *dst, int *dstlen);
/*
 *  Finalizes the base64 context [x], decoding the "final" data remaining
 *    in a partial block into [dst], and setting [dstlen] to the number of
 *    bytes written.
 *  After calling this function, no further updates should be made to [x]
 *    without re-initializing it first.
 *  Returns 0 on success, or -1 on error.
 */

int base64_cleanup (base64_ctx *x);
/*
 *  Clears the base64 context [x].
 *  Returns 0 on success, or -1 on error.
 */

int base64_encode_block (void *dst, int *dstlen, const void *src, int srclen);
/*
 *  Base64-encodes [srclen] bytes from the contiguous [src] into [dst].
 *    If [dstlen] is not NULL, it will be set to the number of bytes written.
 *  Returns 0 on success, or -1 on error.
 */

int base64_decode_block (void *dst, int *dstlen, const void *src, int srclen);
/*
 *  Base64-decodes [srclen] bytes from the contiguous [src] into [dst].
 *    If [dstlen] is not NULL, it will be set to the number of bytes written.
 *  Returns 0 on success, or -1 on error.
 */

int base64_encode_length (int srclen);
/*
 *  Returns the size (in bytes) of the destination memory block required
 *    for base64 encoding a block of [srclen] bytes.
 */

int base64_decode_length (int srclen);
/*
 *  Returns the size (in bytes) of the destination memory block required
 *    for base64 decoding a block of [srclen] bytes.
 */


#endif /* !BASE64_H */
