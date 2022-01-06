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
 *****************************************************************************
 *  Refer to "str.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
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


int
strcatf (char *dst, size_t size, const char *fmt, ...)
{
    va_list  vargs;
    char    *p;
    char    *q;
    int      n;
    int      len;
    int      nleft;

    if (!dst || !size) {
        return (0);
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
    va_start (vargs, fmt);
    n = vsnprintf (p, nleft, fmt, vargs);
    va_end (vargs);

    if ((n < 0) || (n >= nleft)) {
        dst[size - 1] = '\0';           /* ensure dst is NUL-terminated */
        return (-1);
    }
    return (len + n);
}


int
strbin2hex (char *dst, size_t dstlen, const void *src, size_t srclen)
{
    const char  bin2hex[] = "0123456789ABCDEF";
    char       *pdst = dst;
    const char *psrc = src;
    int         i;

    if (dstlen < ((srclen * 2) + 1)) {
        errno = EINVAL;
        return (0);
    }
    for (i = 0; i < srclen; i++) {
        *pdst++ = bin2hex[(psrc[i] >> 4) & 0x0f];
        *pdst++ = bin2hex[(psrc[i]     ) & 0x0f];
    }
    *pdst = '\0';
    return (pdst - (char *) dst);
}


int
strhex2bin (void *dst, size_t dstlen, const char *src, size_t srclen)
{
    char       *pdst = dst;
    const char *psrc = src;
    int         i;
    int         c;
    int         n;

    if (dstlen < (srclen + 1) / 2) {
        errno = EINVAL;
        return (0);
    }
    for (i = 0; i < srclen; i++) {
        c = psrc[i];
        if ((c >= '0') && (c <= '9')) {
            n = c - '0';
        }
        else if ((c >= 'A') && (c <= 'F')) {
            n = c - 'A' + 10;
        }
        else if ((c >= 'a') && (c <= 'f')) {
            n = c - 'a' + 10;
        }
        else {
            errno = EINVAL;
            return (0);
        }
        if (i % 2) {
            *pdst++ |= n & 0x0f;
        }
        else {
            *pdst = (n & 0x0f) << 4;
        }
    }
    return ((srclen + 1) / 2);
}


int
strftimet (char *dst, size_t dstlen, const char *tfmt, time_t t)
{
#if HAVE_LOCALTIME_R
    struct tm  tm;
#endif /* !HAVE_LOCALTIME_R */
    struct tm *tm_ptr;
    int        n;

    if ((dst == NULL) || (dstlen == 0) || (tfmt == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    if (t == 0) {
        if (time (&t) == ((time_t) -1)) {
            return (-1);
        }
    }
#if HAVE_LOCALTIME_R
    tm_ptr = localtime_r (&t, &tm);
#else  /* !HAVE_LOCALTIME_R */
    tm_ptr = localtime (&t);            /* FIXME: protect with mutex? */
#endif /* !HAVE_LOCALTIME_R */
    if (tm_ptr == NULL) {
        return (-1);
    }
    n = strftime (dst, dstlen, tfmt, tm_ptr);
    if ((n <= 0) || (n >= dstlen)) {
        /*  On strftime() error, contents of 'dst' are undefined.  */
        return (0);
    }
    return (n);
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
