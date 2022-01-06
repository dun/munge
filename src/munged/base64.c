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


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <string.h>
#include "base64.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  For details on base64 encoding/decoding, refer to
 *    rfc2440 (OpenPGP Message Format) sections 6.3-6.5.
 *
 *  Why am I not using OpenSSL's base64 encoding/decoding functions?
 *    Because they have the following fucked functionality:
 *  For base64-encoding, use of the context results in output that is broken
 *    into 64-character lines; however, EVP_EncodeBlock() output is not broken.
 *  For base64-decoding, use of the context returns the correct length of the
 *    resulting output; however, EVP_DecodeBlock() returns a length that may
 *    be up to two characters too long.
 *  Finally, data base64-encoded via a context has to be decoded via a context,
 *    and data base64-encoded w/o a context has to be decoded w/o a context.
 *  So fuck it, I wrote my own.  :-P
 */

/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define BASE64_MAGIC    0xDEADBEEF
#define BASE64_ERR      0xFF
#define BASE64_IGN      0xFE
#define BASE64_PAD      0xFD
#define BASE64_PAD_CHAR '='


/*****************************************************************************
 *  Static Variables
 *****************************************************************************/

static const unsigned char bin2asc[] = \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char asc2bin[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfe, 0xfe,
    0xfe, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
    0xff, 0xfd, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
};


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

int
base64_init (base64_ctx *x)
{
    assert (x != NULL);

    x->num = 0;
    x->pad = 0;
    assert (x->magic = BASE64_MAGIC);
    assert (!(x->finalized = 0));
    return (0);
}


int
base64_encode_update (base64_ctx *x, void *vdst, int *dstlen,
                      const void *vsrc, int srclen)
{
    int n;
    int num_read;
    int num_write;
    unsigned char *dst = (unsigned char *) vdst;
    unsigned char *src = (unsigned char *) vsrc;

    assert (x != NULL);
    assert (x->magic == BASE64_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);
    assert (dstlen != NULL);
    assert (src != NULL);

    num_write = 0;

    if (srclen <= 0) {
        return (0);
    }
    /*  Encode leftover data if context buffer can be filled.
     */
    if ((x->num > 0) && (srclen >= (num_read = 3 - x->num))) {
        memcpy (&x->buf[x->num], src, num_read);
        src += num_read;
        srclen -= num_read;
        base64_encode_block (dst, &n, x->buf, 3);
        x->num = 0;
        dst += n;
        num_write += n;
    }
    /*  Encode maximum amount of data w/o requiring a pad.
     */
    if (srclen >= 3) {
        num_read = (srclen / 3) * 3;
        base64_encode_block (dst, &n, src, num_read);
        src += num_read;
        srclen -= num_read;
        num_write += n;
    }
    /*  Save leftover data for the next update() or final().
     */
    if (srclen > 0) {
        memcpy (&x->buf[x->num], src, srclen);
        x->num += srclen;
    }
    *dstlen = num_write;
    return (0);
}


int
base64_encode_final (base64_ctx *x, void *dst, int *dstlen)
{
    assert (x != NULL);
    assert (x->magic == BASE64_MAGIC);
    assert (x->finalized != 1);
    assert (dst != NULL);
    assert (dstlen != NULL);

    /*  Encode leftover data from the previous update().
     */
    if (x->num > 0) {
        base64_encode_block (dst, dstlen, x->buf, x->num);
        x->num = 0;
    }
    else {
        *dstlen = 0;
    }
    assert (x->finalized = 1);
    return (0);
}


int
base64_decode_update (base64_ctx *x, void *dst, int *dstlen,
                      const void *src, int srclen)
{
/*  Context [x] should only be NULL when called via base64_decode_block().
 */
    int                  i = 0;
    int                  err = 0;
    int                  pad = 0;
    unsigned char       *pdst;
    const unsigned char *psrc;
    const unsigned char *psrc_last;
    unsigned char        c;

    assert ((x == NULL) || (x->magic == BASE64_MAGIC));
    assert ((x == NULL) || (x->finalized != 1));
    assert (dst != NULL);
    assert (dstlen != NULL);
    assert (src != NULL);

    pdst = dst;
    psrc = src;
    psrc_last = psrc + srclen;

    /*  Restore context.
     */
    if (x != NULL) {
        i = x->num;
        pad = x->pad;
        *pdst = x->buf[0];
    }
    while (psrc < psrc_last) {
        c = asc2bin[*psrc++];
        if (c == BASE64_IGN) {
            continue;
        }
        if ((c == BASE64_PAD) && (pad < 2)) {
            pad++;
            continue;
        }
        if ((c == BASE64_ERR) || (pad > 0)) {
            err++;
            break;
        }
        switch (i) {
            case 0:
                *pdst    = (c << 2) & 0xfc;
                break;
            case 1:
                *pdst++ |= (c >> 4) & 0x03;
                *pdst    = (c << 4) & 0xf0;
                break;
            case 2:
                *pdst++ |= (c >> 2) & 0x0f;
                *pdst    = (c << 6) & 0xc0;
                break;
            case 3:
                *pdst++ |= (c     ) & 0x3f;
                break;
        }
        i = (i + 1) % 4;
    }
    /*  Save context.
     */
    if (x != NULL) {
        x->num = i;
        x->pad = pad;
        x->buf[0] = *pdst;
    }
    /*  Check for the correct amount of padding.
     */
    else if (!err) {
        err = (((i + pad) % 4) != 0);
    }
    *pdst = '\0';
    *dstlen = pdst - (unsigned char *) dst;
    return (err ? -1 : 0);
}


int
base64_decode_final (base64_ctx *x, void *dst, int *dstlen)
{
    int rc = 0;

    assert (x != NULL);
    assert (x->magic == BASE64_MAGIC);
    assert (x->finalized != 1);

    if (((x->num + x->pad) % 4) != 0) {
        rc = -1;
    }
    *dstlen = 0;
    assert (x->finalized = 1);
    return (rc);
}


int
base64_cleanup (base64_ctx *x)
{
    assert (x != NULL);
    assert (x->magic == BASE64_MAGIC);

    memset (x, 0, sizeof (*x));
    assert (x->magic = ~BASE64_MAGIC);
    return (0);
}


int
base64_encode_block (void *dst, int *dstlen, const void *src, int srclen)
{
    unsigned char       *pdst;
    const unsigned char *psrc;
    int                  n;

    pdst = dst;
    psrc = src;
    n = 0;
    while (srclen >= 3) {
        *pdst++ = bin2asc[ (psrc[0] >> 2) & 0x3f];
        *pdst++ = bin2asc[((psrc[0] << 4) & 0x30) | ((psrc[1] >> 4) & 0x0f)];
        *pdst++ = bin2asc[((psrc[1] << 2) & 0x3c) | ((psrc[2] >> 6) & 0x03)];
        *pdst++ = bin2asc[ (psrc[2]     ) & 0x3f];
        psrc += 3;
        srclen -= 3;
        n += 4;
    }
    if (srclen == 2) {
        *pdst++ = bin2asc[ (psrc[0] >> 2) & 0x3f];
        *pdst++ = bin2asc[((psrc[0] << 4) & 0x30) | ((psrc[1] >> 4) & 0x0f)];
        *pdst++ = bin2asc[ (psrc[1] << 2) & 0x3c];
        *pdst++ = '=';
        n += 4;
    }
    else if (srclen == 1) {
        *pdst++ = bin2asc[ (psrc[0] >> 2) & 0x3f];
        *pdst++ = bin2asc[ (psrc[0] << 4) & 0x30];
        *pdst++ = '=';
        *pdst++ = '=';
        n += 4;
    }
    *pdst = '\0';
    *dstlen = n;
    return (0);
}


int
base64_decode_block (void *dst, int *dstlen, const void *src, int srclen)
{
    return (base64_decode_update (NULL, dst, dstlen, src, srclen));
}


int
base64_encode_length (int srclen)
{
/*  When encoding, 3 bytes are encoded into 4 characters.
 *  Add 2 bytes to ensure a partial 3-byte chunk will be accounted for
 *    during integer division, then add 1 byte for the terminating NUL.
 */
    return (((srclen + 2) / 3) * 4) + 1;
}


int
base64_decode_length (int srclen)
{
/*  When decoding, 4 characters are decoded into 3 bytes.
 *  Add 3 bytes to ensure a partial 4-byte chunk will be accounted for
 *    during integer division, then add 1 byte for the terminating NUL.
 */
    return (((srclen + 3) / 4) * 3) + 1;
}


/*****************************************************************************
 *  Table Initialization Routines
 *****************************************************************************/

#ifdef BASE64_INIT


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>


#define BASE64_DEF_COLS 12


void base64_build_table (unsigned char *data, int len);
void base64_print_table (unsigned char *data, int len, char *name, int col);


int
main (int argc, char *argv[])
{
    int col;
    unsigned char a2b[256];

    col = (argc > 1) ? atoi (argv[1]) : BASE64_DEF_COLS;

    base64_build_table (a2b, sizeof (a2b));
    base64_print_table (a2b, sizeof (a2b), "asc2bin", col);
    exit (EXIT_SUCCESS);
}


void
base64_build_table (unsigned char *data, int len)
{
    int i;

    for (i = 0; i < len; i++)
        data[i] = (isspace (i)) ? BASE64_IGN : BASE64_ERR;
    for (i = strlen (bin2asc) - 1; i >= 0; i--)
        data[bin2asc[i]] = i;
    data[BASE64_PAD_CHAR] = BASE64_PAD;
    return;
}


void
base64_print_table (unsigned char *data, int len, char *name, int col)
{
    int i;
    int n;

    if (col < 1) {
       col = BASE64_DEF_COLS;
    }
    printf ("static const unsigned char %s[%d] = {", name, len);

    for (i=0, n=len-1; ; i++) {
        if ((i % col) == 0)
            printf ("\n    ");
        printf ("0x%02x", data[i]);
        if (i == n)
            break;
        printf (", ");
    }
    printf ("\n};\n");
    return;
}


#endif /* BASE64_INIT */
