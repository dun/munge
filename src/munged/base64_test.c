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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "tap.h"


/*****************************************************************************
 *  Test cases from RFC 2440 (OpenPGP Message Format)
 *    Section 6.5 (Examples of Radix-64).
 *****************************************************************************/


int validate (const char *dst, const void *src, int srclen);
int encode_block (char *dst, int *dstlen, const void *src, int srclen);
int encode_context (char *dst, int *dstlen, const void *src, int srclen);
int decode_block (char *dst, int *dstlen, const void *src, int srclen);
int decode_context (char *dst, int *dstlen, const void *src, int srclen);


int
main (int argc, char *argv[])
{
    const unsigned char src1[] = { 0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e };
    const unsigned char src2[] = { 0x14, 0xfb, 0x9c, 0x03, 0xd9 };
    const unsigned char src3[] = { 0x14, 0xfb, 0x9c, 0x03 };

    const char dst1[] = "FPucA9l+";
    const char dst2[] = "FPucA9k=";
    const char dst3[] = "FPucAw==";

    plan (3);

    ok (validate (dst1, src1, sizeof (src1)) == 0,
            "Input data 0x14fb9c03d97e");

    ok (validate (dst2, src2, sizeof (src2)) == 0,
            "Input data 0x14fb9c03d9");

    ok (validate (dst3, src3, sizeof (src3)) == 0,
            "Input data 0x14fb9c03");

    done_testing ();

    exit (EXIT_SUCCESS);
}


int
validate (const char *dst, const void *src, int srclen)
{
    int n;
    char buf[9];

    if (encode_block (buf, &n, src, srclen) < 0)
        return (-1);
    if (n != strlen (dst))
        return (-1);
    if (strncmp (dst, buf, n))
        return (-1);

    if (decode_block (buf, &n, dst, strlen (dst)) < 0)
        return (-1);
    if (n != srclen)
        return (-1);
    if (strncmp (src, buf, n))
        return (-1);

    if (encode_context (buf, &n, src, srclen) < 0)
        return (-1);
    if (n != strlen (dst))
        return (-1);
    if (strncmp (dst, buf, n))
        return (-1);

    if (decode_context (buf, &n, dst, strlen (dst)) < 0)
        return (-1);
    if (n != srclen)
        return (-1);
    if (strncmp (src, buf, n))
        return (-1);

    return (0);
}


int
encode_block (char *dst, int *dstlen, const void *src, int srclen)
{
    return (base64_encode_block (dst, dstlen, src, srclen));
}


int
encode_context (char *dst, int *dstlen, const void *src, int srclen)
{
    base64_ctx x;
    int i;
    int n;
    int m;
    const unsigned char *p = src;

    if (base64_init (&x) < 0)
        return (-1);
    for (i = 0, n = 0; i < srclen; i++) {
        if (base64_encode_update (&x, dst, &m, p + i, 1) < 0)
            return (-1);
        dst += m;
        n += m;
    }
    if (base64_encode_final (&x, dst, &m) < 0)
        return (-1);
    if (base64_cleanup (&x) < 0)
        return (-1);
    n += m;
    *dstlen = n;
    return (0);
}


int
decode_block (char *dst, int *dstlen, const void *src, int srclen)
{
    return (base64_decode_block (dst, dstlen, src, srclen));
}


int
decode_context (char *dst, int *dstlen, const void *src, int srclen)
{
    base64_ctx x;
    int i;
    int n;
    int m;
    const unsigned char *p = src;

    if (base64_init (&x) < 0)
        return (-1);
    for (i = 0, n = 0; i < srclen; i++) {
        if (base64_decode_update (&x, dst, &m, p + i, 1) < 0)
            return (-1);
        dst += m;
        n += m;
    }
    if (base64_decode_final (&x, dst, &m) < 0)
        return (-1);
    if (base64_cleanup (&x) < 0)
        return (-1);
    n += m;
    *dstlen = n;
    return (0);
}
