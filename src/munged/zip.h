/*****************************************************************************
 *  $Id: zip.h,v 1.2 2004/04/03 01:12:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-155910.
 *
 *  Copyright (C) 2004 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
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
    void *dst, int *dstlen, const void *src, int srclen);
/*
 *  Compresses the [src] buffer of length [srclen] in a single pass using the
 *    compression method [type].  The resulting compressed output is stored
 *    in the [dst] buffer.
 *  Upon entry, [*dstlen] must be set to the size of the [dst] buffer.
 *  Upon exit, [*dstlen] is set to the size of the compressed data.
 *  Returns 0 on success, or -1 or error.
 */

int zip_decompress_block (munge_zip_t type,
    void *dst, int *dstlen, const void *src, int srclen);
/*
 *  Decompresses the [src] buffer of length [srclen] in a single pass using the
 *    compression method [type].  The resulting decompressed (original) output
 *    is stored in the [dst] buffer.
 *  Upon entry, [*dstlen] must be set to the size of the [dst] buffer.
 *  Upon exit, [*dstlen] is set to the size of the decompressed data.
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
