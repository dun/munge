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
#include "hkdf.h"
#include "md.h"
#include "tap.h"


int
main (int argc, char *argv[])
{
    hkdf_ctx_t    *hkdfp;
    size_t         buflen;
    unsigned char  buf[8200];
    unsigned char  vanillabuf[8200];
    unsigned char  partialbuf[13];

    crypto_init ();
    md_init_subsystem ();

    /*  initialize bufs with different data in preparation for memcmp tests
     */
    memset (buf, 1, sizeof (buf));
    memset (vanillabuf, 2, sizeof (vanillabuf));
    memset (partialbuf, 3, sizeof (partialbuf));

    plan (NO_PLAN);

    ok ((hkdfp = hkdf_ctx_create ()) != NULL,
            "hkdf_ctx_create");

    if (hkdfp == NULL) {
        BAIL_OUT ("Testing cannot proceed without hkdf ctx");
    }
    /*  validate hkdf() with null parms and unset md
     */
    buflen = sizeof (buf);
    ok (hkdf (NULL, buf, &buflen) < 0 && (errno == EINVAL),
            "hkdf failure for null ctx ptr");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, NULL, &buflen) < 0 && (errno == EINVAL),
            "hkdf failure for null dst ptr");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, NULL) < 0 && (errno == EINVAL),
            "hkdf failure for null dstlenp value-result");

    /*  validate hkdf_ctx_set_md()
     */
    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) < 0,
            "hkdf failure for unset md");

    ok (hkdf_ctx_set_md (NULL, MUNGE_MAC_SHA256) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_md failure for null ctx ptr");

    ok (hkdf_ctx_set_md (hkdfp, 1313) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_md failure for invalid md");

    ok (hkdf_ctx_set_md (hkdfp, MUNGE_MAC_SHA256) == 0,
            "hkdf_ctx_set_md success");

    /*  validate hkdf_ctx_set_key()
     */
    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) < 0,
            "hkdf failure for unset key");

    ok (hkdf_ctx_set_key (NULL, "xyzzy", 5) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_key failure for null ctx ptr");

    ok (hkdf_ctx_set_key (hkdfp, NULL, 0) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_key failure for null key ptr");

    ok (hkdf_ctx_set_key (hkdfp, "xyzzy", 5) == 0,
            "hkdf_ctx_set_key success for nonzero-length key");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) == 0,
            "hkdf success for nonzero-length key");

    /*  vanillabuf with SHA256, zero-length key, no salt, no info
     */
    ok (hkdf_ctx_set_key (hkdfp, "", 0) == 0,
            "hkdf_ctx_set_key success for zero-length key");

    ok (sizeof (vanillabuf) == sizeof (buf),
            "hkdf vanillabuf size matches buf size");

    buflen = sizeof (vanillabuf);
    ok (hkdf (hkdfp, vanillabuf, &buflen) == 0,
            "hkdf success for zero-length key");

    ok (memcmp (buf, vanillabuf, buflen) != 0,
            "hkdf differing keys yield differing bufs");

    /*  max dstlen = mdlen * HKDF_MAX_ROUNDS = 32 * 255 = 8160 bytes
     */
    ok (sizeof (buf) > 32 * 255,
            "hkdf buf size suitable for max dst check");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) == 0,
            "hkdf success for max dst");

    ok (buflen == 32 * 255,
            "hkdf buflen correct for max dst");

    ok (memcmp (vanillabuf, buf, buflen) == 0,
            "hkdf matching keys yield matching bufs");

    /*  partialbuf must be smaller than the SHA256 block size of 32 bytes
     */
    ok (sizeof (partialbuf) < 32,
            "hkdf buf size suitable for partial md block check");

    buflen = sizeof (partialbuf);
    ok (hkdf (hkdfp, partialbuf, &buflen) == 0,
            "hkdf success for partial md block");

    ok (buflen == sizeof (partialbuf),
            "hkdf buflen correct for partial md block");

    ok (memcmp (vanillabuf, partialbuf, buflen) == 0,
            "hkdf buf from partial md block matches partial buf");

    /*  validate hkdf_ctx_set_salt()
     */
    ok (hkdf_ctx_set_salt (NULL, "salt", 4) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_salt failure for null ctx ptr");

    ok (hkdf_ctx_set_salt (hkdfp, NULL, 0) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_salt failure for null salt ptr");

    ok (hkdf_ctx_set_salt (hkdfp, "salt", 4) == 0,
            "hkdf_ctx_set_salt success for nonzero-length salt");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) == 0,
            "hkdf success for nonzero-length salt");

    ok (memcmp (vanillabuf, buf, buflen) != 0,
            "hkdf differing salts yield differing bufs");

    ok (hkdf_ctx_set_salt (hkdfp, "", 0) == 0,
            "hkdf_ctx_set_salt success for zero-length salt");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) == 0,
            "hkdf success for zero-length salt");

    ok (memcmp (vanillabuf, buf, buflen) == 0,
            "hkdf buf from zero-length salt matches vanilla buf");

    /*  validate hkdf_ctx_set_info()
     */
    ok (hkdf_ctx_set_info (NULL, "info", 4) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_info failure for null ctx ptr");

    ok (hkdf_ctx_set_info (hkdfp, NULL, 0) < 0 && (errno == EINVAL),
            "hkdf_ctx_set_info failure for null info ptr");

    ok (hkdf_ctx_set_info (hkdfp, "info", 4) == 0,
            "hkdf_ctx_set_info success for nonzero-length info");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) == 0,
            "hkdf success for nonzero-length info");

    ok (memcmp (vanillabuf, buf, buflen) != 0,
            "hkdf differing infos yield differing bufs");

    ok (hkdf_ctx_set_info (hkdfp, "", 0) == 0,
            "hkdf_ctx_set_info success for zero-length info");

    buflen = sizeof (buf);
    ok (hkdf (hkdfp, buf, &buflen) == 0,
            "hkdf success for zero-length info");

    ok (memcmp (vanillabuf, buf, buflen) == 0,
            "hkdf buf from zero-length info matches vanilla buf");

    /*  cleanup
    */
    hkdf_ctx_destroy (hkdfp);

    done_testing ();

    crypto_fini ();

    exit (EXIT_SUCCESS);
}
