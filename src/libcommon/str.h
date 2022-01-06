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


#ifndef STR_H
#define STR_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <time.h>
#include <sys/types.h>


char * strdupf (const char *fmt, ...);
/*
 *  Duplicates the string specified by the format-string [fmt].
 *  Returns the new string, or NULL if out of memory.
 *  The caller is responsible for free()ing this new string.
 */

int strcatf (char *dst, size_t size, const char *fmt, ...);
/*
 *  Concatenates the string specified by the format-string [fmt] to
 *    the NUL-terminated string [dst] within a buffer of size [size].
 *    Note that [size] is the full size of [dst], not the space remaining.
 *  Returns the new length of the NUL-terminated string [dst], or -1 if
 *    truncation occurred.  The string in [dst] is guaranteed to be
 *    NUL-terminated.
 */

int strbin2hex (char *dst, size_t dstlen, const void *src, size_t srclen);
/*
 *  Converts the buffer [src] of length [srclen] into a NUL-terminated
 *    hexadecimal string, storing the result in the buffer [dst] of
 *    length [dstlen].
 *  Returns the length of the NUL-terminated string [dst], or 0 if the
 *    buffer [dst] is too small (ie, less than ((srclen * 2) + 1) bytes).
 */

int strhex2bin (void *dst, size_t dstlen, const char *src, size_t srclen);
/*
 *  Converts the first [srclen] characters of the hexadecimal string [src]
 *    into a binary representation, storing the result in the buffer [dst]
 *    of length [dstlen].
 *  Returns the number of bytes of binary data in [dst], or 0 on error --
 *    if the buffer [dst] is too small (ie, less than ((srclen + 1) / 2) bytes)
 *    or contains non-hexadecimal digits.
 */

int strftimet (char *dst, size_t dstlen, const char *tfmt, time_t t);
/*
 *  Formats the time [t] to the local time according to the strftime()
 *    format [tfmt], storing the resulting string in the buffer [dst] of
 *    length [dstlen].
 *  Returns the length of the NUL-terminated string [dst], -1 on error
 *    (with errno set), or 0 if truncation occurred.  Upon success (ie, >0),
 *    the string in [dst] is guaranteed to be NUL-terminated.
 *  If [t] is 0, the current time will be used.
 */

void * memburn (void *v, int c, size_t n);
/*
 *  Implementation of memset to prevent "dead store removal" optimization,
 *    thereby ensuring secrets are overwritten.
 *  Fills the first [n] bytes of the memory area pointed to by [v]
 *    with the constant byte [c].
 *  Returns a pointer to the memory area [v].
 */


#endif /* !STR_H */
