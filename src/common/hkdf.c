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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <munge.h>
#include "common.h"
#include "hkdf.h"
#include "log.h"
#include "mac.h"
#include "str.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************
 *
 *  Implementation based on RFC 5869: HMAC-based Extract-and-Expand
 *    Key Derivation Function (HKDF).
 *
 *  Refer to "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
 *    (2010) by Hugo Krawczyk for further details.
 */


/*****************************************************************************
 *  Constants
 *****************************************************************************/

/*  As per RFC 5869: For HKDF-Expand, the output keying material (OKM) is
 *    calculated by generating sufficient octets of T(1)...T(N), where
 *    N = ceil (L / HashLen).  L (length of OKM in octets) <= 255 * HashLen.
 *    HashLen denotes the length of the hash function output in octets.
 *    Thus, the maximum number of rounds is 255.
 *  Furthermore, the number of the round concatenated to the end of each T(n)
 *    is a single octet which architecturally limits it to 255.
 */
#define HKDF_MAX_ROUNDS 255


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct hkdf_ctx {
    unsigned     salt_is_allocated:1;
    munge_mac_t  md;                    /* message digest / hash function    */
    size_t       mdlen;                 /* length of MD output (in bytes)    */
    const void  *key;                   /* input keying material             */
    size_t       keylen;                /* length of key (in bytes)          */
    const void  *salt;                  /* optional: non-secret random value */
    size_t       saltlen;               /* length of salt (in bytes)         */
    const void  *info;                  /* optional: context specific info   */
    size_t       infolen;               /* length of info (in bytes)         */
};


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static int _hkdf_extract (hkdf_ctx_t *ctxp, void *prk, size_t *prklenp);

static int _hkdf_expand (hkdf_ctx_t *ctxp, const void *prk, size_t prklen,
        void *dst, size_t *dstlenp);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Create a new HKDF context.
 *  Return a ptr to the context on success, or NULL on error.
 */
hkdf_ctx_t *
hkdf_ctx_create (void)
{
    hkdf_ctx_t *ctxp;

    ctxp = calloc (1, sizeof (*ctxp));
    return ctxp;
}


/*  Destroy the HKDF context [ctxp].
 */
void
hkdf_ctx_destroy (hkdf_ctx_t *ctxp)
{
    if (ctxp == NULL) {
        return;
    }
    if ((ctxp->key != NULL) && (ctxp->keylen > 0)) {
        ctxp->key = NULL;
        ctxp->keylen = 0;
    }
    if ((ctxp->salt != NULL) && (ctxp->saltlen > 0)) {
        if (ctxp->salt_is_allocated) {
            free ((void *) ctxp->salt);
            ctxp->salt_is_allocated = 0;
        }
        ctxp->salt = NULL;
        ctxp->saltlen = 0;
    }
    if ((ctxp->info != NULL) && (ctxp->infolen > 0)) {
        ctxp->info = NULL;
        ctxp->infolen = 0;
    }
    free (ctxp);
}


/*  Specify the message digest / hash function [md] for use with the
 *    HKDF context [ctxp].
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
hkdf_ctx_set_md (hkdf_ctx_t *ctxp, munge_mac_t md)
{
    if (ctxp == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mac_map_enum (md, NULL) < 0) {
        errno = EINVAL;
        return -1;
    }
    ctxp->md = md;
    return 0;
}


/*  Specify the input keying material [key] of length [keylen] for use with
 *    the HKDF context [ctxp].
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
hkdf_ctx_set_key (hkdf_ctx_t *ctxp, const void *key, size_t keylen)
{
    if ((ctxp == NULL) || (key == NULL)) {
        errno = EINVAL;
        return -1;
    }
    ctxp->key = key;
    ctxp->keylen = keylen;
    return 0;
}


/*  Specify an optional [salt] of length [saltlen] for use with the
 *    HKDF context [ctxp].
 *  The salt is a non-secret random value; if not provided, it is set to a
 *    string of zeros equal in length to the size of the hash function output.
 *  The use of salt adds significantly to the strength of HKDF, ensuring
 *    independence between different uses of the hash function, supporting
 *    source-independent extraction, and strengthening the analytical results
 *    that back the HKDF design.
 *  Ideally, the salt value is a random (or pseudorandom) string equal in
 *    length to the size of the hash function output.  Yet, even a salt value
 *    of less quality (i.e., shorter in size, or with limited entropy) may
 *    still make a significant contribution to the security of the output
 *    keying material.
 *  The salt value should be independent of the input keying material.
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
hkdf_ctx_set_salt (hkdf_ctx_t *ctxp, const void *salt, size_t saltlen)
{
    if ((ctxp == NULL) || (salt == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (ctxp->salt_is_allocated) {
        free ((void *) ctxp->salt);
        ctxp->salt_is_allocated = 0;
    }
    ctxp->salt = salt;
    ctxp->saltlen = saltlen;
    return 0;
}


/*  Specify optional context and application specific information [info]
 *    of length [infolen] for use with the HKDF context [ctxp].
 *  This information binds the derived key material to application- and
 *    context-specific information.
 *  This information should be independent of the input keying material.
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
hkdf_ctx_set_info (hkdf_ctx_t *ctxp, const void *info, size_t infolen)
{
    if ((ctxp == NULL) || (info == NULL)) {
        errno = EINVAL;
        return -1;
    }
    ctxp->info = info;
    ctxp->infolen = infolen;
    return 0;
}


/*  Compute the HMAC-based Key Derivation Function (HKDF) based on the
 *    HKDF context [ctxp].
 *  The resulting output keying material will be written into the buffer [dst].
 *    [dstlenp] is a value-result parameter; it must be initialized to the size
 *    of the [dst] buffer (in bytes).
 *  Return 0 on success (with [*dstlenp] set to the number of bytes written
 *    into the [dst] buffer), or -1 on error (with errno set).
 */
int
hkdf (hkdf_ctx_t *ctxp, void *dst, size_t *dstlenp)
{
    unsigned char *prk = NULL;          /* pseudorandom key                  */
    size_t         prklen;              /* length of PRK (in bytes)          */
    size_t         prklen_used;         /* length of PRK used (in bytes)     */
    int            rv;

    if ((ctxp == NULL) || (dst == NULL) || (dstlenp == NULL)) {
        errno = EINVAL;
        return -1;
    }
    /*  Validate mac.
     *  ctx is initialized with 0 which equates to MUNGE_MAC_NONE which is
     *    invalid by definition.  The mac will be validated by mac_size() when
     *    computing the length of the hash function output.
     */
    ctxp->mdlen = (size_t) mac_size (ctxp->md);
    if (ctxp->mdlen == (size_t) -1) {
        errno = EINVAL;
        return -1;
    }
    /*  Validate key.
     *  A zero-length key seems to be allowed, but the key ptr must not be NULL
     *    due to assertions in mac.c.
     */
    if (ctxp->key == NULL) {
        errno = EINVAL;
        return -1;
    }
    /*  Allocate salt, if not already set.
     */
    if (ctxp->salt == NULL) {
        ctxp->saltlen = ctxp->mdlen;
        ctxp->salt = calloc (1, ctxp->saltlen);
        if (ctxp->salt == NULL) {
            return -1;
        }
        ctxp->salt_is_allocated = 1;
    }
    /*  Allocate pseudorandom key.
     *  The length of the PRK is the length of the hash function output.
     */
    prklen = ctxp->mdlen;
    prk = calloc (1, prklen);
    if (prk == NULL) {
        return -1;
    }
    prklen_used = prklen;               /* initialize value-result parm */
    /*
     *  Extract pseudorandom key.
     */
    rv = _hkdf_extract (ctxp, prk, &prklen_used);
    if (rv == -1) {
        goto cleanup;
    }
    if (prklen != prklen_used) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed HKDF Extraction: expected %u bytes, received %u bytes",
                prklen, prklen_used);
    }
    /*  Expand pseudorandom key to desired length.
     */
    rv = _hkdf_expand (ctxp, prk, prklen, dst, dstlenp);

cleanup:
    if (prk != NULL) {
        memburn (prk, 0, prklen);
        free (prk);
    }
    return rv;
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

/*  HKDF First Stage.
 *  Extract (or concentrate) the possibly dispersed entropy of the input
 *    keying material into a short, but cryptographically strong,
 *    pseudorandom key (prk).
 *  [prklenp] is a value-result parameter; it must be initialized to the size
 *    of the [prk] buffer (in bytes).
 *  Return 0 on success (with [*prklenp] set to the number of bytes written
 *    into the [prk] buffer), or -1 on error (with errno set).
 */
static int
_hkdf_extract (hkdf_ctx_t *ctxp, void *prk, size_t *prklenp)
{
    mac_ctx mac_ctx;
    int     mac_ctx_is_initialized = 0;
    int     prklen;
    int     rv = 0;

    assert (ctxp != NULL);
    assert (ctxp->salt != NULL);
    assert (ctxp->key != NULL);
    assert (prk != NULL);
    assert (prklenp != NULL);
    assert (*prklenp > 0);

    /*  Convert prklen size_t to int for the call to mac_final() since the parm
     *    is being passed as a ptr, and size of size_t and int may differ.
     *  *prklenp must be representable as an int because it was assigned
     *    (via ctxp->mdlen) by mac_size() which returns an int.
     */
    assert (*prklenp <= INT_MAX);
    prklen = (int) *prklenp;

    /*  Compute the pseudorandom key.
     *    prk = HMAC (salt, ikm)
     */
    rv = mac_init (&mac_ctx, ctxp->md, ctxp->salt, ctxp->saltlen);
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to initialize HKDF MAC ctx for extraction");
        goto err;
    }
    mac_ctx_is_initialized = 1;

    rv = mac_update (&mac_ctx, ctxp->key, ctxp->keylen);
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to update HKDF MAC ctx for extraction");
        goto err;
    }
    rv = mac_final (&mac_ctx, prk, &prklen);
    if (rv == -1) {
        log_msg (LOG_ERR, "Failed to finalize HKDF MAC ctx for extraction");
        goto err;
    }
err:
    if (mac_ctx_is_initialized) {
        if (mac_cleanup (&mac_ctx) == -1) {
            log_msg (LOG_ERR, "Failed to cleanup HKDF MAC ctx for extraction");
            return -1;
        }
    }
    /*  Update [prklenp] on success.
     */
    if (rv >= 0) {
        assert (prklen >= 0);
        *prklenp = (size_t) prklen;
    }
    return rv;
}


/*  HKDF Second Stage.
 *  Expand the pseudorandom key [prk] of length [prklen] to the desired length,
 *    writing the output keying material into the buffer [dst].
 *  [dstlenp] is a value-result parameter; it must be initialized to the size
 *    of the [dst] buffer (in bytes).
 *  Return 0 on success (with [*dstlenp] set to the number of bytes written
 *    into the [dst] buffer), or -1 on error (with errno set).
 */
static int
_hkdf_expand (hkdf_ctx_t *ctxp, const void *prk, size_t prklen,
              void *dst, size_t *dstlenp)
{
    unsigned char *dstp;
    size_t         dstlen_left;
    unsigned char *okm = NULL;
    int            okmlen;
    unsigned char  round;
    mac_ctx        mac_ctx;
    int            mac_ctx_is_initialized = 0;
    int            n;
    int            rv = 0, rv2;

    assert (ctxp != NULL);
    assert (prk != NULL);
    assert (prklen > 0);
    assert (dst != NULL);
    assert (dstlenp != NULL);

    dstp = dst;
    dstlen_left = *dstlenp;

    /*  Allocate buffer for output keying material.
     *  The buffer size is equal to the size of the hash function output.
     *  Note that okmlen must be an int (and not size_t) for the call to
     *    mac_final() since the parm is being passed as a ptr, and size of
     *    size_t and int may differ.
     *  ctxp->mdlen must be representable as an int because it was assigned
     *    by mac_size() which returns an int.
     */
    assert (ctxp->mdlen <= INT_MAX);
    okmlen = (int) ctxp->mdlen;
    okm = calloc (1, okmlen);
    if (okm == NULL) {
        rv = -1;
        goto err;
    }
    /*  Compute output keying material for each expansion round.
     *    okm(i) = HMAC (prk, okm(i-i) | [info] | i)
     */
    round = 0;
    while (dstlen_left > 0) {
        round++;

        rv = mac_init (&mac_ctx, ctxp->md, prk, prklen);
        if (rv == -1) {
            log_msg (LOG_ERR,
                    "Failed to initialize HKDF MAC ctx "
                    "for expansion round #%u", round);
            goto err;
        }
        mac_ctx_is_initialized = 1;

        if (round > 1) {
            rv = mac_update (&mac_ctx, okm, okmlen);
            if (rv == -1) {
                log_msg (LOG_ERR,
                        "Failed to update HKDF MAC ctx with prev okm "
                        "for expansion round #%u", round);
                goto err;
            }
        }
        if (ctxp->infolen > 0) {
            rv = mac_update (&mac_ctx, ctxp->info, ctxp->infolen);
            if (rv == -1) {
                log_msg (LOG_ERR,
                        "Failed to update HKDF MAC ctx with info "
                        "for expansion round #%u", round);
                goto err;
            }
        }
        assert (sizeof (round) == 1);
        rv = mac_update (&mac_ctx, &round, sizeof (round));
        if (rv == -1) {
            log_msg (LOG_ERR,
                    "Failed to update HKDF MAC ctx with count "
                    "for expansion round #%u", round);
            goto err;
        }
        rv = mac_final (&mac_ctx, okm, &okmlen);
        if (rv == -1) {
            log_msg (LOG_ERR,
                    "Failed to finalize HKDF MAC ctx "
                    "for expansion round #%u", round);
            goto err;
        }
        rv = mac_cleanup (&mac_ctx);
        mac_ctx_is_initialized = 0;
        if (rv == -1) {
            log_msg (LOG_ERR, "Failed to cleanup HKDF MAC ctx for expansion");
            goto err;
        }
        assert (okmlen == ctxp->mdlen);
        n = MIN(okmlen, dstlen_left);
        memcpy (dstp, okm, n);
        dstp += n;
        dstlen_left -= n;

        if (round == HKDF_MAX_ROUNDS) {
            break;
        }
    }
    *dstlenp = dstp - (unsigned char *) dst;
err:
    if (mac_ctx_is_initialized) {
        rv2 = mac_cleanup (&mac_ctx);
        if (rv2 == -1) {
            log_msg (LOG_ERR, "Failed to cleanup HKDF MAC ctx for expansion");
            rv = -1;
        }
    }
    if (okm != NULL) {
        memburn (okm, 0, ctxp->mdlen);
        free (okm);
    }
    return rv;
}
