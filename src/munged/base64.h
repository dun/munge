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

int base64_encode_update (base64_ctx *x, void *dst, int *dstlen,
                          const void *src, int srclen);

int base64_encode_final (base64_ctx *x, void *dst, int *dstlen);

int base64_decode_update (base64_ctx *x, void *dst, int *dstlen,
                          const void *src, int srclen);

int base64_decode_final (base64_ctx *x, void *dst, int *dstlen);

int base64_cleanup (base64_ctx *x);

int base64_encode_block (void *dst, int *dstlen, const void *src, int srclen);

int base64_decode_block (void *dst, int *dstlen, const void *src, int srclen);

int base64_encode_length (int srclen);

int base64_decode_length (int srclen);


#endif /* !BASE64_H */
