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
 *  <https://www.gnu.org/licenses/>.
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

int zip_compress_block (munge_zip_t type,
    void *dst, int *pdstlen, const void *src, int srclen);

int zip_decompress_block (munge_zip_t type,
    void *dst, int *pdstlen, const void *src, int srclen);

int zip_compress_length (munge_zip_t type, const void *src, int len);

int zip_decompress_length (munge_zip_t type, const void *src, int len);

munge_zip_t zip_select_default_type (munge_zip_t type);


#endif /* !ZIP_H */
