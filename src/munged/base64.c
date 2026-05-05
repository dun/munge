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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include "base64.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>                     /* INT_MAX */
#include <string.h>                     /* memcpy, memset, strlen */

/**
 *  Notes
 *
 *  For details on base64 encoding/decoding, refer to
 *  rfc2440 (OpenPGP Message Format) sections 6.3-6.5.
 *
 *  OpenSSL's base64 API has inconsistent behavior:
 *  - For encoding: context-based functions insert line breaks at 64 chars,
 *    but EVP_EncodeBlock() does not.
 *  - For decoding: context-based functions return accurate output length,
 *    but EVP_DecodeBlock() may overestimate by up to two bytes.
 *  - Data encoded via a context must be decoded via a context;
 *    data encoded without a context must be decoded without a context.
 *
 *  This custom implementation provides consistent, predictable behavior.
 */

#define BASE64_ERR      0xFF
#define BASE64_IGN      0xFE
#define BASE64_PAD      0xFD
#define BASE64_PAD_CHAR '='

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

/**
 *  Initialize the base64 context [x] for base64 encoding/decoding.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_init (base64_ctx *x)
{
    if (!x) {
        errno = EINVAL;
        return -1;
    }
    x->num = 0;
    x->pad = 0;
    assert (!(x->finalized = 0));
    return 0;
}

/**
 *  Update the base64 context [x] by encoding [srclen] bytes from [src]
 *  into [dst], setting [dstlen] to the number of bytes written.
 *
 *  Call this multiple times to process successive blocks of data.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_encode_update (base64_ctx *x, void *vdst, int *dstlen,
                      const void *vsrc, int srclen)
{
    int n;
    int num_read;
    int num_write;
    unsigned char *dst = (unsigned char *) vdst;
    const unsigned char *src = (const unsigned char *) vsrc;

    if (!x || !vdst || !dstlen || !vsrc || srclen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (srclen == 0) {
        return 0;
    }
    assert (x->finalized != 1);

    num_write = 0;

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
    return 0;
}

/**
 *  Finalize the base64 context [x] by encoding remaining data from a partial
 *  block into [dst], setting [dstlen] to the number of bytes written.
 *
 *  Do not make further updates to [x] without re-initializing it first.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_encode_final (base64_ctx *x, void *dst, int *dstlen)
{
    if (!x || !dst || !dstlen) {
        errno = EINVAL;
        return -1;
    }
    assert (x->finalized != 1);

    /*  Encode leftover data from the previous update().
     */
    if (x->num > 0) {
        base64_encode_block (dst, dstlen, x->buf, x->num);
        x->num = 0;
    }
    else {
        *dstlen = 0;
    }
    assert ((x->finalized = 1));
    return 0;
}

/**
 *  Update the base64 context [x] by decoding [srclen] bytes from [src]
 *  into [dst], setting [dstlen] to the number of bytes written.
 *
 *  Call this multiple times to process successive blocks of data.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 *
 *  Note: Context [x] may be NULL when called via base64_decode_block().
 */
int
base64_decode_update (base64_ctx *x, void *dst, int *dstlen,
                      const void *src, int srclen)
{
    int i = 0;
    int err = 0;
    int pad = 0;
    unsigned char *pdst;
    const unsigned char *psrc;
    const unsigned char *psrc_last;
    unsigned char c;

    if (!dst || !dstlen || !src || srclen < 0) {
        errno = EINVAL;
        return -1;
    }
    pdst = dst;
    psrc = src;
    psrc_last = psrc + srclen;

    /*  Restore context.
     */
    if (x != NULL) {
        assert (x->finalized != 1);
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
            errno = EBADMSG;
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
        if (err) {
            errno = EBADMSG;
        }
    }
    *pdst = '\0';
    *dstlen = pdst - (unsigned char *) dst;
    return (err ? -1 : 0);
}

/**
 *  Finalize the base64 context [x], setting [dstlen] to the number of bytes
 *  written to [dst].
 *
 *  Do not make further updates to [x] without re-initializing it first.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_decode_final (base64_ctx *x, void *dst, int *dstlen)
{
    int rc = 0;

    if (!x || !dst || !dstlen) {
        errno = EINVAL;
        return -1;
    }
    assert (x->finalized != 1);

    if (((x->num + x->pad) % 4) != 0) {
        errno = EBADMSG;
        rc = -1;
    }
    *dstlen = 0;
    assert ((x->finalized = 1));
    return rc;
}

/**
 *  Clear the base64 context [x], zeroing all fields.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_cleanup (base64_ctx *x)
{
    if (!x) {
        errno = EINVAL;
        return -1;
    }
    memset (x, 0, sizeof *x);
    return 0;
}

/**
 *  Base64-encode [srclen] bytes from [src] into [dst], setting [dstlen]
 *  to the number of bytes written.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_encode_block (void *dst, int *dstlen, const void *src, int srclen)
{
    unsigned char *pdst;
    const unsigned char *psrc;
    int n;

    if (!dst || !dstlen || !src || srclen < 0) {
        errno = EINVAL;
        return -1;
    }
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
    return 0;
}

/**
 *  Base64-decode [srclen] bytes from [src] into [dst], setting [dstlen]
 *  to the number of bytes written.
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
base64_decode_block (void *dst, int *dstlen, const void *src, int srclen)
{
    return base64_decode_update (NULL, dst, dstlen, src, srclen);
}

/**
 *  Calculate the buffer size (in bytes) required for base64 encoding
 *  [srclen] bytes.
 *
 *  Return the required size, or -1 on error (with errno set).
 */
int
base64_encode_length (int srclen)
{
    const int maxlen = (((INT_MAX - 1) / 4) * 3) - 2;

    if (srclen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (srclen > maxlen) {
        errno = ERANGE;
        return -1;
    }
/*  When encoding, 3 bytes are encoded into 4 characters.
 *  Add 2 bytes to ensure a partial 3-byte chunk will be accounted for
 *  during integer division, then add 1 byte for the terminating null byte.
 */
    return (((srclen + 2) / 3) * 4) + 1;
}

/**
 *  Calculate the buffer size (in bytes) required for base64 decoding
 *  [srclen] bytes.
 *
 *  Return the required size, or -1 on error (with errno set).
 */
int
base64_decode_length (int srclen)
{
/*  Use unsigned arithmetic to prevent constant-expression overflow on ILP32
 *  platforms where sizeof(int) == sizeof(long).
 */
    const unsigned maxlen = (((unsigned) (INT_MAX - 1) / 3) * 4) - 3;

    if (srclen < 0) {
        errno = EINVAL;
        return -1;
    }
    if ((unsigned) srclen > maxlen) {
        errno = ERANGE;
        return -1;
    }
/*  When decoding, 4 characters are decoded into 3 bytes.
 *  Add 3 bytes to ensure a partial 4-byte chunk will be accounted for
 *  during integer division, then add 1 byte for the terminating null byte.
 */
    return (((srclen + 3) / 4) * 3) + 1;
}

/******************************************************************************
 *  Table Initialization Routines
 */

#ifdef MUNGE_BASE64_INIT

#include <ctype.h>                      /* isspace */
#include <stdio.h>                      /* printf */
#include <stdlib.h>                     /* atoi, exit, EXIT_SUCCESS */

#define BASE64_DEF_COLS 12

void base64_build_table (unsigned char *data, int len);
void base64_print_table (unsigned char *data, int len, char *name, int col);

int
main (int argc, char *argv[])
{
    int col;
    unsigned char a2b[256];

    col = (argc > 1) ? atoi (argv[1]) : BASE64_DEF_COLS;

    base64_build_table (a2b, sizeof a2b);
    base64_print_table (a2b, sizeof a2b, "asc2bin", col);
    exit (EXIT_SUCCESS);
}

void
base64_build_table (unsigned char *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        data[i] = (isspace (i)) ? BASE64_IGN : BASE64_ERR;
    }
    for (i = strlen (bin2asc) - 1; i >= 0; i--) {
        data[bin2asc[i]] = i;
    }
    data[BASE64_PAD_CHAR] = BASE64_PAD;
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
        if ((i % col) == 0) {
            printf ("\n    ");
        }
        printf ("0x%02x", data[i]);
        if (i == n) {
            break;
        }
        printf (", ");
    }
    printf ("\n};\n");
}

#endif /* MUNGE_BASE64_INIT */
