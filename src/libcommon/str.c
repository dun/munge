/*****************************************************************************
 *  $Id: str.c,v 1.3 2004/01/28 01:04:59 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2001-2003 The Regents of the University of California.
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
 *****************************************************************************
 *  Refer to "str.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "str.h"


#ifndef MAX_STR_SIZE
#  define MAX_STR_SIZE 1024
#endif /* !MAX_STR_SIZE */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

char *
strdupf (const char *fmt, ...)
{
    va_list  vargs;
    char     buf[MAX_STR_SIZE];
    char    *p;

    if (!fmt) {
        return (NULL);
    }
    va_start (vargs, fmt);
    vsnprintf (buf, sizeof (buf), fmt, vargs);
    va_end (vargs);

    buf[sizeof (buf) - 1] = '\0';        /* ensure buf is NUL-terminated */

    if (!(p = strdup (buf))) {
        return (NULL);
    }
    return (p);
}


size_t
strcatf (char *dst, size_t size, const char *fmt, ...)
{
    va_list  vargs;
    char    *p;
    char    *q;
    int      n;
    int      len;
    int      nleft;

    if (!dst || !size) {
        return(0);
    }
    p = dst;
    q = dst + size;
    while ((*p) && (p < q)) {           /* walk dst in case NUL not present */
        p++;
    }
    len = p - dst;
    if (len >= size) {                  /* dst not NUL-terminated */
        dst[size - 1] = '\0';
        return (-1);
    }
    if (!fmt || !*fmt) {                /* nothing to concatenate */
        return (len);
    }
    nleft = size - len;
    if (nleft <= 1) {                   /* dst already full */
        return (-1);
    }
    va_start(vargs, fmt);
    n = vsnprintf(p, nleft, fmt, vargs);
    va_end(vargs);

    if ((n < 0) || (n >= nleft)) {
        dst[size - 1] = '\0';           /* ensure dst is NUL-terminated */
        return(-1);
    }
    return(len + n);
}


void
strdump (const char *prefix, void *x, int n)
{
    unsigned char *p = x;
    int i;

    printf ("%s:%d:", prefix, n);
    for (i=0; i<n; i++)
        printf ("%02x", p[i]);
    printf ("\n");
    return;
}


void *
memburn (void *v, int c, size_t n)
{
/*  From David A. Wheeler's "Secure Programming for Linux and Unix HOWTO"
 *    <http://www.dwheeler.com/secure-programs/> (section 11.4):
 *  Many compilers, including many C/C++ compilers, remove writes to stores
 *    that are no longer used -- this is often referred to as "dead store
 *    removal".  Unfortunately, if the write is really to overwrite the value
 *    of a secret, this means that code that appears to be correct will be
 *    silently discarded.
 *  One approach that seems to work on all platforms is to write your own
 *    implementation of memset with internal "volatilization" of the first
 *    argument (this code is based on a workaround proposed by Michael Howard):
 */
    volatile char *p = v;

    while (n--) {
        *p++ = c;
    }
    return (v);
}
