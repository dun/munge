/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2001-2005 The Regents of the University of California.
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


#ifndef STR_H
#define STR_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>


char * strdupf (const char *fmt, ...);
/*
 *  Duplicates the string specified by the format-string [fmt].
 *  Returns the new string, or NULL if out of memory.
 *  The caller is responsible for freeing this new string.
 */

size_t strcatf (char *dst, size_t size, const char *fmt, ...);
/*
 *  Concatenates the string specified by the format-string [fmt] to
 *    the NUL-terminated string [dst] within a buffer of size [size].
 *    Note that [size] is the full size of [dst], not the space remaining.
 *  Returns the new length of the NUL-terminated string [dst],
 *    or -1 if truncation occurred.  The string in [dst] is
 *    guaranteed to be NUL-terminated.
 */

char * strhex (void *dst, size_t dstlen, const void *src, size_t srclen);
/*
 *  Converts the buf [src] of length [srclen] to hexadecimal notation, storing
 *    the resulting NUL-terminated string in buf [dst] of length [dstlen].
 *  Returns a ptr to [dst], or NULL if the [dst] buffer is too small
 *    (ie, less than ((srclen * 2) + 1) bytes).
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
