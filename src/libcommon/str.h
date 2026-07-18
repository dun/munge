/******************************************************************************
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


#ifndef MUNGE_STR_H
#define MUNGE_STR_H


#include "attr.h"

#include <stddef.h>                     /* size_t */
#include <time.h>                       /* time_t */


char * strdupf (const char *fmt, ...)
    ATTR_FORMAT (__printf__, 1, 2);

int strcatf (char *dst, size_t size, const char *fmt, ...)
    ATTR_FORMAT (__printf__, 3, 4);

int strbin2hex (char *dst, size_t dstlen, const void *src, size_t srclen);

int strhex2bin (void *dst, size_t dstlen, const char *src, size_t srclen);

int strftimet (char *dst, size_t dstlen, const char *tfmt, time_t t)
    ATTR_FORMAT (__strftime__, 3, 0);


#endif /* MUNGE_STR_H */
