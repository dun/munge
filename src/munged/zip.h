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


#ifndef ZIP_H
#define ZIP_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <munge.h>
#include "common.h"                     /* HAVE_PKG_BZLIB, HAVE_PKG_ZLIB */


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

int zip_is_valid_type (munge_zip_t type);
/*
 *  Returns non-zero if the given [type] is a supported valid MUNGE compression
 *    type according to the current configuration.  The NONE and DEFAULT types
 *    are not considered valid types by this routine.
 */

int zip_compress_block (munge_zip_t type,
    void *dst, int *pdstlen, const void *src, int srclen);
/*
 *  Compresses the [src] buffer of length [srclen] in a single pass using the
 *    compression method [type].  The resulting compressed output is stored
 *    in the [dst] buffer.
 *  Upon entry, [*pdstlen] must be set to the size of the [dst] buffer.
 *  Upon exit, [*pdstlen] is set to the size of the compressed data.
 *  Returns 0 on success, or -1 or error.
 */

int zip_decompress_block (munge_zip_t type,
    void *dst, int *pdstlen, const void *src, int srclen);
/*
 *  Decompresses the [src] buffer of length [srclen] in a single pass using the
 *    compression method [type].  The resulting decompressed (original) output
 *    is stored in the [dst] buffer.
 *  Upon entry, [*pdstlen] must be set to the size of the [dst] buffer.
 *  Upon exit, [*pdstlen] is set to the size of the decompressed data.
 *  Returns 0 on success, or -1 or error.
 */

int zip_compress_length (munge_zip_t type, const void *src, int len);
/*
 *  Returns a worst-case estimate for the buffer length needed to compress data
 *    in the [src] buffer of length [len] using the compression method [type],
 *    or -1 on error.
 */

int zip_decompress_length (munge_zip_t type, const void *src, int len);
/*
 *  Returns the decompressed (original) length of the compressed data
 *    in the [src] buffer of length [len], or -1 on error.
 */

munge_zip_t zip_select_default_type (munge_zip_t type);
/*
 *  Returns [type] if that compression type is supported by the current
 *    configuration; otherwise, returns an acceptible default type.
 */


#endif /* !ZIP_H */
