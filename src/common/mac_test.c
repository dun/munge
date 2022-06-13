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
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <munge.h>
#include "crypto.h"
#include "mac.h"
#include "md.h"
#include "tap.h"


int
check_mac (munge_mac_t m, const char *str, const char *key, int keylen,
        const char *src, int srclen, const unsigned char *dst, int dstlen)
{
    unsigned char buf[64];
    int buflen;
    mac_ctx ctx;
    int rv;

    if (!str) {
        fail ("check_mac empty str for mac #%d", (int) m);
        return -1;
    }
    if (!key || (keylen <= 0)) {
        fail ("check_mac invalid key or keylen for %s", str);
        return -1;
    }
    if (!src || (srclen <= 0)) {
        fail ("check_mac invalid src or srclen for %s", str);
        return -1;
    }
    if (!dst || (dstlen <= 0)) {
        fail ("check_mac invalid dst or dstlen for %s", str);
        return -1;
    }
    if (dstlen > sizeof (buf)) {
        fail ("check_mac %ld-byte buf too small for %s %d-byte result",
                sizeof (buf), str, dstlen);
        return -1;
    }
    ok (mac_size (m) == dstlen, "mac_size %s is %d", str, dstlen);

    ok (!mac_map_enum (m, NULL), "mac_map_enum %s", str);

    buflen = sizeof (buf);
    memset (buf, 0, sizeof (buf));
    ok (!mac_block (m, key, keylen, buf, &buflen, src, srclen),
            "mac_block %s", str);
    ok (buflen == dstlen, "mac_block %s outlen", str);
    cmp_mem (buf, dst, dstlen, "mac_block %s output", str);

    buflen = sizeof (buf);
    memset (buf, 0, sizeof (buf));
    ok (!(rv = mac_init (&ctx, m, key, keylen)), "mac_init %s", str);
    ok (!rv && !(rv = mac_update (&ctx, src, srclen)), "mac_update %s", str);
    ok (!rv && !(rv = mac_final (&ctx, buf, &buflen)), "mac_final %s", str);
    ok (buflen == dstlen, "mac_final %s outlen", str);
    cmp_mem (buf, dst, dstlen, "mac_final %s output", str);
    ok (!rv && !(rv = mac_cleanup (&ctx)), "mac_cleanup %s", str);

    return rv;
}


int
main (int argc, char *argv[])
{
    const char *key = "magic words";
    const char *in = "squeamish ossifrage";
    const unsigned char out_md5[16] = {
        0x89, 0x98, 0xc9, 0xb1, 0xb6, 0xf9, 0xfd, 0xd6, 0x6f, 0x3a, 0x5c, 0x0a,
        0xf9, 0x22, 0x69, 0x60
    };
    const unsigned char out_sha1[20] = {
        0x1e, 0x17, 0x06, 0x6e, 0x61, 0x71, 0xe5, 0x75, 0x7a, 0xcf, 0x1c, 0x99,
        0x35, 0x04, 0x14, 0x36, 0x7f, 0x98, 0x33, 0xe5
    };
    const unsigned char out_ripemd160[20] = {
        0x11, 0x68, 0x37, 0x52, 0x26, 0xcd, 0xc5, 0xfe, 0xb7, 0xb9, 0xce, 0x45,
        0x0c, 0xfc, 0x73, 0xd9, 0x68, 0x3c, 0xaf, 0xa2
    };
    const unsigned char out_sha256[32] = {
        0xcb, 0xc1, 0xa8, 0xe6, 0x30, 0x0d, 0x7f, 0x92, 0xb0, 0xbe, 0x65, 0x97,
        0x6a, 0xe3, 0x61, 0x47, 0x61, 0x44, 0x81, 0x4a, 0xfc, 0xac, 0x1e, 0x6b,
        0x81, 0xbb, 0xf6, 0x81, 0x9c, 0x31, 0xda, 0x0f
    };
    const unsigned char out_sha512[64] = {
        0xa1, 0x3d, 0x45, 0x37, 0x3a, 0xad, 0x58, 0x08, 0xa4, 0x31, 0x0b, 0x9b,
        0xd5, 0xb7, 0x88, 0xd4, 0x64, 0x86, 0xf2, 0x26, 0xbe, 0x0d, 0x7e, 0xcc,
        0xd9, 0xcf, 0xab, 0x8d, 0x88, 0x0f, 0x9d, 0x35, 0xa9, 0x66, 0x2a, 0x78,
        0xfa, 0x87, 0x6a, 0x62, 0x89, 0x3c, 0x1c, 0x1e, 0x87, 0xcb, 0x13, 0x2e,
        0xef, 0x39, 0x87, 0xac, 0xb3, 0xb9, 0x7e, 0x73, 0x10, 0x9b, 0xae, 0xde,
        0xce, 0x1b, 0xd4, 0x79
    };

    crypto_init ();
    md_init_subsystem ();

    plan (NO_PLAN);

    check_mac (MUNGE_MAC_MD5, "MUNGE_MAC_MD5", key, strlen (key),
            in, strlen (in), out_md5, sizeof (out_md5));

    check_mac (MUNGE_MAC_SHA1, "MUNGE_MAC_SHA1", key, strlen (key),
            in, strlen (in), out_sha1, sizeof (out_sha1));

    check_mac (MUNGE_MAC_RIPEMD160, "MUNGE_MAC_RIPEMD160", key, strlen (key),
            in, strlen (in), out_ripemd160, sizeof (out_ripemd160));

    check_mac (MUNGE_MAC_SHA256, "MUNGE_MAC_SHA256", key, strlen (key),
            in, strlen (in), out_sha256, sizeof (out_sha256));

    check_mac (MUNGE_MAC_SHA512, "MUNGE_MAC_SHA512", key, strlen (key),
            in, strlen (in), out_sha512, sizeof (out_sha512));

    done_testing ();

    crypto_fini ();

    exit (EXIT_SUCCESS);
}
