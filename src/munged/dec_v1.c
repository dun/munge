/*****************************************************************************
 *  $Id: dec_v1.c,v 1.19 2004/04/16 22:15:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>
#include <string.h>
#include "auth.h"
#include "base64.h"
#include "cipher.h"
#include "conf.h"
#include "cred.h"
#include "dec_v1.h"
#include "gids.h"
#include "lookup.h"
#include "mac.h"
#include "md.h"
#include "msg_server.h"
#include "munge_defs.h"
#include "munge_msg.h"
#include "random.h"
#include "replay.h"
#include "str.h"
#include "zip.h"


/*****************************************************************************
 *  Extern Variables
 *****************************************************************************/

extern conf_t conf;                     /* defined in munged.c               */


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static int dec_v1_validate_msg (munge_msg_t m);
static int dec_v1_timestamp (munge_cred_t c);
static int dec_v1_authenticate (munge_cred_t c);
static int dec_v1_unarmor (munge_cred_t c);
static int dec_v1_unpack_outer (munge_cred_t c);
static int dec_v1_decrypt (munge_cred_t c);
static int dec_v1_decompress (munge_cred_t c);
static int dec_v1_unpack_inner (munge_cred_t c);
static int dec_v1_validate_mac (munge_cred_t c);
static int dec_v1_validate_time (munge_cred_t c);
static int dec_v1_validate_auth (munge_cred_t c);
static int dec_v1_validate_replay (munge_cred_t c);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

int
dec_v1_process_msg (munge_msg_t m)
{
    munge_cred_t c = NULL;              /* aux data for processing this cred */
    int          rc = -1;               /* return code                       */

    if (dec_v1_validate_msg (m) < 0)
        ;
    else if (!(c = cred_create (m)))
        ;
    else if (dec_v1_timestamp (c) < 0)
        ;
    else if (dec_v1_authenticate (c) < 0)
        ;
    else if (dec_v1_unarmor (c) < 0)
        ;
    else if (dec_v1_unpack_outer (c) < 0)
        ;
    else if (dec_v1_decrypt (c) < 0)
        ;
    else if (dec_v1_decompress (c) < 0)
        ;
    else if (dec_v1_validate_mac (c) < 0)
        ;
    else if (dec_v1_unpack_inner (c) < 0)
        ;
    else if (dec_v1_validate_auth (c) < 0)
        ;
    else if (dec_v1_validate_time (c) < 0)
        ;
    else if (dec_v1_validate_replay (c) < 0)
        ;
    else /* success */
        rc = 0;

    if (rc < 0) {
        err_v1_response (m);
    }
    if (_munge_msg_send (m) != EMUNGE_SUCCESS) {
        rc = -1;
    }
    cred_destroy (c);
    return (rc);
}


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static int
dec_v1_validate_msg (munge_msg_t m)
{
/*  Validates a credential exists for decoding.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */

    assert (m != NULL);
    assert (m->head.version == 1);
    assert (m->head.type == MUNGE_MSG_DEC_REQ);

    m1 = m->pbody;

    /*  Reset message type for the response.
     *  From this point on, now that the return message type is set,
     *    errors are returned to the client instead of being silently dropped.
     */
    m->head.type = MUNGE_MSG_DEC_RSP;

    if ((m1->data_len == 0) || (m1->data == NULL)) {
        return (_munge_msg_set_err (m, EMUNGE_SNAFU,
            strdup ("No credential specified in decode request")));
    }
    return (0);
}


static int
dec_v1_timestamp (munge_cred_t c)
{
/*  Queries the current time.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    time_t now;

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    /*  Set the "decode" time.
     */
    if (time (&now) == ((time_t) -1)) {
        return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU,
            strdup ("Unable to query current time")));
    }
    m1->time0 = 0;
    m1->time1 = now;                    /* potential 64b value for 32b var */
    return (0);
}


static int
dec_v1_authenticate (munge_cred_t c)
{
/*  Ascertains the UID/GID of the client process.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */

    assert (c != NULL);
    assert (c->msg);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    /*  Determine identity of client process.
     */
    if (auth_peer_get (c->msg->sd, &(m1->client_uid), &(m1->client_gid)) < 0) {
        return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU,
            strdup ("Unable to determine identity of client")));
    }
    return (0);
}


static int
dec_v1_unarmor (munge_cred_t c)
{
/*  Removes the credential's armor, converting it into a packed byte array.
 *  The armor consists of PREFIX + BASE64 [ OUTER + MAC + INNER ] + SUFFIX.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    int                  prefix_len;    /* prefix string length              */
    int                  suffix_len;    /* prefix string length              */
    int                  base64_len;    /* length of base64 data             */
    unsigned char       *base64_ptr;    /* base64 data (ptr into msg data)   */
    unsigned char       *base64_tmp;    /* base64 data tmp ptr               */
    int                  n;             /* all-purpose int                   */

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    prefix_len = strlen (MUNGE_CRED_PREFIX);
    suffix_len = strlen (MUNGE_CRED_SUFFIX);

    base64_ptr = m1->data;
    base64_len = m1->data_len;

    /*  Consume leading whitespace.
     */
    while ((base64_len > 0) && isspace (*base64_ptr)) {
        base64_ptr++;
        base64_len--;
    }
    if ((base64_len == 0) || (*base64_ptr == '\0')) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_ARG,
            strdup ("No credential specified")));
    }
    /*  Remove the prefix string.
     *  The prefix specifies the start of the base64-encoded data.
     */
    if (prefix_len > 0) {
        if (strncmp ((char *) base64_ptr, MUNGE_CRED_PREFIX, prefix_len)) {
            return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
                strdup ("Unable to match armor prefix")));
        }
        base64_ptr += prefix_len;
        base64_len -= prefix_len;
    }
    /*  Remove the suffix string.
     *  The suffix specifies the end of the base64-encoded data.
     *    We can't rely on the base64 pad character to detect the end,
     *    since that only exists if the input isn't a multiple of 3 bytes.
     *  However, the suffix isn't strictly necessary since whitespace
     *    is safely ignored by the base64 decoding routine.
     *  Still, it's nice to have a quick visual test to see if it's all there.
     *
     *  XXX: This may be somewhat inefficient if the suffix isn't there.
     *       If all goes well, the suffix will match on the 3rd comparison
     *       due to the trailing "\n\0".
     */
    if (suffix_len > 0) {
        base64_tmp = base64_ptr + base64_len - suffix_len;
        while (base64_tmp >= base64_ptr) {
            if (!strncmp ((char *) base64_tmp, MUNGE_CRED_SUFFIX, suffix_len))
                break;
            base64_tmp--;
        }
        if (base64_tmp < base64_ptr) {
            return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
                strdup ("Unable to match armor suffix")));
        }
        base64_len = base64_tmp - base64_ptr;
    }
    /*  Allocate memory for unarmor'd data.
     */
    c->outer_mem_len = base64_decode_length (base64_len);
    if (!(c->outer_mem = malloc (c->outer_mem_len))) {
        return (_munge_msg_set_err (c->msg, EMUNGE_NO_MEMORY, NULL));
    }
    /*  Base64-decode the chewy-internals of the credential.
     */
    if (base64_decode_block (c->outer_mem, &n, base64_ptr, base64_len) < 0) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Unable to base64-decode credential")));
    }
    assert (n < c->outer_mem_len);

    /*  Note outer_len is an upper bound which will be refined when unpacked.
     *  It currently includes OUTER + MAC + INNER.
     */
    c->outer = c->outer_mem;
    c->outer_len = n;
    return (0);
}


static int
dec_v1_unpack_outer (munge_cred_t c)
{
/*  Unpacks the "outer" credential data from MSBF (ie, big endian) format.
 *  The "outer" part of the credential does not undergo cryptographic
 *    transformations (ie, compression and encryption).  It includes:
 *    cred version, cipher type, compression type, mac type, realm length,
 *    unterminated realm string (if realm_len > 0), and the cipher's
 *    initialization vector (if encrypted).
 *  Validation of the "outer" credential occurs here as well since unpacking
 *    may not be able to continue if an invalid field is found.
 *  While the MAC is not technically part of the "outer" credential data,
 *    it is unpacked here since it resides in outer_mem and its location
 *    (along with the location of the "inner" data) is determined as a
 *    result of unpacking the "outer" data.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    unsigned char       *p;             /* ptr into packed data              */
    int                  len;           /* length of packed data remaining   */
    int                  n;             /* all-purpose int                   */
    const EVP_CIPHER    *ci;            /* symmetric cipher algorithm        */
    const EVP_MD        *md;            /* message difest algorithm          */

    assert (c != NULL);
    assert (c->outer != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    /*  Initialize.
     */
    m1 = c->msg->pbody;
    p = c->outer;
    len = c->outer_len;
    /*
     *  Unpack the credential version.
     *  Note that only one version (ie, the latest) of the credential format
     *    is currently supported.  Support for multiple versions would
     *    require a switch on the version number to invoke the appropriate
     *    unpack routine, but it doesn't really seem worth the effort.
     */
    n = sizeof (c->version);
    assert (n == 1);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential version")));
    }
    c->version = *p;
    if ((!c->version) || (c->version != MUNGE_CRED_VERSION)) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_VERSION,
            strdupf ("Unsupported credential version %d", c->version)));
    }
    p += n;
    len -= n;
    /*
     *  Unpack the cipher type.
     */
    n = sizeof (m1->cipher);
    assert (n == 1);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential cipher type")));
    }
    m1->cipher = *p;
    ci = lookup_cipher (m1->cipher);
    if ((m1->cipher != MUNGE_CIPHER_NONE) && (!ci)) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CIPHER,
            strdupf ("Invalid cipher type %d", m1->cipher)));
    }
    c->dek_len = cipher_key_size (ci);
    assert (c->dek_len <= sizeof (c->dek));
    c->iv_len = cipher_iv_size (ci);
    assert (c->iv_len <= sizeof (c->iv));
    p += n;
    len -= n;
    /*
     *  Unpack the compression type.
     */
    n = sizeof (m1->zip);
    assert (n == 1);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential compression type")));
    }
    m1->zip = *p;
    if ((m1->zip != MUNGE_ZIP_NONE) && (!zip_is_valid_type (m1->zip))) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_ZIP,
            strdupf ("Invalid compression type %d", m1->zip)));
    }
    p += n;
    len -= n;
    /*
     *  Unpack the message authentication code type.
     */
    n = sizeof (m1->mac);
    assert (n == 1);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential mac type")));
    }
    m1->mac = *p;
    md = lookup_mac (m1->mac);
    if (!md) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_MAC,
            strdupf ("Invalid mac type %d", m1->mac)));
    }
    c->mac_len = md_size (md);
    assert (c->mac_len <= sizeof (c->mac));
    p += n;
    len -= n;
    /*
     *  Unpack the length of realm string.
     */
    n = sizeof (m1->realm_len);
    assert (n == 1);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential realm length")));
    }
    m1->realm_len = *p;
    p += n;
    len -= n;
    /*
     *  Unpack the unterminated realm string (if present).
     *    Note that the realm string is NUL-terminated after unpacking.
     */
    if (m1->realm_len > 0) {
        if (m1->realm_len > len) {
            return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
                strdup ("Truncated credential realm string")));
        }
        c->realm_mem_len = m1->realm_len + 1;
        if (!(c->realm_mem = malloc (c->realm_mem_len))) {
            return (_munge_msg_set_err (c->msg, EMUNGE_NO_MEMORY, NULL));
        }
        memcpy (c->realm_mem, p, m1->realm_len);
        c->realm_mem[m1->realm_len] = '\0';
        p += m1->realm_len;
        len -= m1->realm_len;
        /*
         *  Update realm & realm_len to refer to the string in "cred memory".
         */
        m1->realm = (char *) c->realm_mem;
        m1->realm_len = c->realm_mem_len;
    }
    /*  Unpack the cipher initialization vector (if needed).
     *    The length of the IV was derived from the cipher type.
     */
    if (c->iv_len > 0) {
        if (c->iv_len > len) {
            return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
                strdup ("Truncated credential iv")));
        }
        assert (c->iv_len <= sizeof (c->iv));
        memcpy (c->iv, p, c->iv_len);
        p += c->iv_len;
        len -= c->iv_len;
    }
    /*  Refine outer_len now that we've reached the end of the "outer" data.
     */
    c->outer_len = p - c->outer;
    /*
     *  Unpack the MAC.
     */
    memcpy (c->mac, p, c->mac_len);
    p += c->mac_len;
    len -= c->mac_len;
    /*
     *  We've finally reached the chewy center of the "inner" data.
     */
    c->inner = p;
    c->inner_len = len;
    /*
     *  Since this routine currently only handles version 1 credentials,
     *    initialize the length of the credential salt here as well.
     */
    c->salt_len = MUNGE_CRED_SALT_LEN;
    assert (c->salt_len <= sizeof (c->salt));
    return (0);
}


static int
dec_v1_decrypt (munge_cred_t c)
{
/*  Decrypts the "inner" credential data.
 *
 *  Note that if cipher_final() fails, an error condition is set but an error
 *    status is not returned (yet).  Here's why...
 *  cipher_final() will return an error code during decryption if padding is
 *    enabled and the final block is not correctly formatted.
 *  If block cipher padding errors are not treated the same as MAC verification
 *    errors, an attacker may be able to launch Vaudenay's attack on padding:
 *    - <http://lasecwww.epfl.ch/php_code/publications/search.php?ref=Vau01>
 *    - <http://lasecwww.epfl.ch/php_code/publications/search.php?ref=Vau02a>
 *    - <http://lasecwww.epfl.ch/memo_ssl.shtml>
 *    - <http://www.openssl.org/~bodo/tls-cbc.txt>
 *  Consequently, if cipher_final() returns a failure, the error condition is
 *    set here and the MAC computation in dec_v1_validate_mac() is performed
 *    regardless in order to minimize information leaked via timing.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    const EVP_MD        *md;            /* message digest algorithm          */
    const EVP_CIPHER    *ci;            /* cipher algorithm                  */
    int                  buf_len;       /* length of plaintext buffer        */
    unsigned char       *buf;           /* plaintext buffer                  */
    unsigned char       *buf_ptr;       /* ptr into plaintext buffer         */
    cipher_ctx           x;             /* cipher context                    */
    int                  n, m;          /* all-purpose ints                  */

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    /*  Is this credential encrypted?
     */
    if (m1->cipher == MUNGE_CIPHER_NONE) {
        return (0);
    }
    /*  MAC/Cipher types already checked by dec_v1_unpack_outer().
     */
    md = lookup_mac (m1->mac);
    assert (md != NULL);
    ci = lookup_cipher (m1->cipher);
    assert (ci != NULL);

    /*  Compute DEK.
     *  msg-dek = MAC (msg-mac) using DEK subkey
     */
    c->dek_len = md_size (md);
    assert (c->dek_len <= sizeof (c->dek));
    assert (c->dek_len >= cipher_key_size (ci));

    if (mac_block (md, conf->dek_key, conf->dek_key_len,
                       c->dek, &n, c->mac, c->mac_len) < 0) {
        return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU,
            strdup ("Unable to compute dek")));
    }
    assert (n == c->dek_len);

    /*  Allocate memory for plaintext.
     *  Ensure enough space by allocating an additional cipher block.
     */
    buf_len = c->inner_len + cipher_block_size (ci);
    if (!(buf = malloc (buf_len))) {
        return (_munge_msg_set_err (c->msg, EMUNGE_NO_MEMORY, NULL));
    }
    /*  Decrypt "inner" data.
     */
    if (cipher_init (&x, ci, c->dek, c->iv, CIPHER_DECRYPT) < 0) {
        goto err;
    }
    buf_ptr = buf;
    n = 0;
    if (cipher_update (&x, buf_ptr, &m, c->inner, c->inner_len) < 0) {
        goto err_cleanup;
    }
    buf_ptr += m;
    n += m;
    if (cipher_final (&x, buf_ptr, &m) < 0) {
        /*  Set but defer error until dec_v1_validate_mac().  */
        _munge_msg_set_err (c->msg, EMUNGE_CRED_INVALID, NULL);
    }
    else {
        /*  Only assert invariant upon successful decryption.  */
        assert (n + m <= buf_len);
    }
    buf_ptr += m;
    n += m;
    if (cipher_cleanup (&x) < 0) {
        goto err;
    }
    /*  Replace "inner" ciphertext with plaintext.
     */
    assert (c->inner_mem == NULL);
    assert (c->inner_mem_len == 0);
    c->inner_mem = buf;
    c->inner_mem_len = buf_len;
    c->inner = buf;
    c->inner_len = n;
    return (0);

err_cleanup:
    cipher_cleanup (&x);
err:
    memset (buf, 0, buf_len);
    free (buf);
    return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU,
        strdup ("Unable to decrypt credential")));
}


static int
dec_v1_decompress (munge_cred_t c)
{
/*  Decompresses the "inner" credential data.
 *
 *  Note that if zip_decompress_block() returns a failure, an error condition
 *    is set but an error status is not returned (yet) for the same reason as
 *    in dec_v1_decrypt().  Instead, the dec_v1_validate_mac() MAC computation
 *    is still performed in order to minimize information leaked via timing.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    unsigned char       *buf;           /* decompression buffer              */
    int                  buf_len;       /* length of decompression buffer    */
    int                  n;             /* length of decompressed data       */

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    /*  Is this credential compressed?
     */
    if (m1->zip == MUNGE_ZIP_NONE) {
        return (0);
    }
    /*  Compression type already checked by dec_v1_unpack_outer().
     */
    assert (zip_is_valid_type (m1->zip));
    /*
     *  Allocate memory for decompressed "inner" data.
     */
    buf = NULL;
    buf_len = zip_decompress_length (m1->zip, c->inner, c->inner_len);
    if (buf_len < 0) {
        goto err;
    }
    if (!(buf = malloc (buf_len))) {
        _munge_msg_set_err (c->msg, EMUNGE_NO_MEMORY, NULL);
        goto err;
    }
    /*  Decompress "inner" data.
     */
    n = buf_len;
    if (zip_decompress_block (m1->zip, buf, &n, c->inner, c->inner_len) < 0) {
        /*  Set but defer error until dec_v1_validate_mac().  */
        _munge_msg_set_err (c->msg, EMUNGE_CRED_INVALID, NULL);
    }
    else {
        /*  Only assert invariant upon successful decompression.  */
        assert (n == buf_len);
    }
    /*
     *  Replace compressed data with "inner" data.
     */
    if (c->inner_mem) {
        assert (c->inner_mem_len > 0);
        memset (c->inner_mem, 0, c->inner_mem_len);
        free (c->inner_mem);
    }
    c->inner_mem = buf;
    c->inner_mem_len = buf_len;
    c->inner = buf;
    c->inner_len = n;
    return (0);

err:
    if ((buf_len > 0) && (buf != NULL)) {
        memset (buf, 0, buf_len);
        free (buf);
    }
    return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU,
        strdup ("Unable to decompress credential")));
}


static int
dec_v1_validate_mac (munge_cred_t c)
{
/*  Validates the Message Authentication Code (MAC) over the entire message
 *    (ie, both "outer" and "inner" data).
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    const EVP_MD        *md;            /* message digest algorithm          */
    mac_ctx              x;             /* message auth code context         */
    unsigned char        mac[MAX_MAC];  /* message authentication code       */
    int                  n;             /* all-purpose int                   */

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    /*  MAC type already checked by dec_v1_unpack_outer().
     */
    md = lookup_mac (m1->mac);
    assert (md != NULL);
    assert (mac_size (md) <= sizeof (mac));

    /*  Compute MAC.
     */
    if (mac_init (&x, md, conf->mac_key, conf->mac_key_len) < 0) {
        goto err;
    }
    if (mac_update (&x, c->outer, c->outer_len) < 0) {
        goto err_cleanup;
    }
    if (mac_update (&x, c->inner, c->inner_len) < 0) {
        goto err_cleanup;
    }
    if (mac_final (&x, mac, &n) < 0) {
        goto err_cleanup;
    }
    if (mac_cleanup (&x) < 0) {
        goto err;
    }
    assert (n <= sizeof (mac));

    /*  Validate new computed MAC against old received MAC.
     */
    if ((n != c->mac_len) || (memcmp (mac, c->mac, c->mac_len) != 0)) {
        return (_munge_msg_set_err (c->msg, EMUNGE_CRED_INVALID, NULL));
    }
    /*  Ensure an invalid cred error from before is caught
     *    (if it wasn't somehow already caught by the MAC validation).
     */
    if (c->msg->errnum != EMUNGE_SUCCESS) {
        return (-1);
    }
    return (0);

err_cleanup:
    mac_cleanup (&x);
err:
    return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU,
        strdup ("Unable to mac credential")));
}


static int
dec_v1_unpack_inner (munge_cred_t c)
{
/*  Unpacks the "inner" credential data from MSBF (ie, big endian) format.
 *  The "inner" part of the credential may have been subjected to cryptographic
 *    transformations (ie, compression and encryption).  It includes:
 *    salt, ip addr len, origin ip addr, encode time, ttl, uid, gid,
 *    data length, and data (if present).
 *  Validation of the "inner" credential occurs here as well since unpacking
 *    may not be able to continue if an invalid field is found.
 *
 *  Note that specific error messages are set here.  My initial thought was
 *    to return generic error messages here in order to ensure information was
 *    not leaked that could help further an attack.  But the MAC has already
 *    been validated as this point, so it should be safe to be specific.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    unsigned char       *p;             /* ptr into packed data              */
    int                  len;           /* length of packed data remaining   */
    int                  n;             /* all-purpose int                   */
    uint32_t             u;             /* all-purpose uint32                */

    assert (c != NULL);
    assert (c->inner != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    /*  Initialize.
     */
    m1 = c->msg->pbody;
    p = c->inner;
    len = c->inner_len;
    /*
     *  Unpack the salt.
     *  Add it to the PRNG entropy pool if it's encrypted.
     */
    if (c->salt_len > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential salt")));
    }
    memcpy (c->salt, p, c->salt_len);
    if (m1->cipher != MUNGE_CIPHER_NONE) {
        random_add (c->salt, c->salt_len);
    }
    p += c->salt_len;
    len -= c->salt_len;
    /*
     *  Unpack the length of the origin IP address.
     */
    n = sizeof (m1->addr_len);
    assert (n == 1);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential origin ip addr length")));
    }
    m1->addr_len = *p;                  /* a single byte is always aligned */
    p += n;
    len -= n;
    /*
     *  Unpack the origin IP address.
     */
    if (m1->addr_len != sizeof (m1->addr)) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Invalid credential origin ip addr length")));
    }
    if (m1->addr_len > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential origin ip addr")));
    }
    memcpy (&m1->addr, p, m1->addr_len);
    p += m1->addr_len;
    len -= m1->addr_len;
    /*
     *  Unpack the encode time.
     */
    n = sizeof (m1->time0);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential encode time")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->time0 = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the time-to-live.
     */
    n = sizeof (m1->ttl);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential time-to-live")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->ttl = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the UID.
     */
    n = sizeof (m1->cred_uid);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential uid")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->cred_uid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the GID.
     */
    n = sizeof (m1->cred_gid);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential gid")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->cred_gid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the UID restriction for authorization.
     */
    n = sizeof (m1->auth_uid);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated uid restriction")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->auth_uid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the GID restriction for authorization.
     */
    n = sizeof (m1->auth_gid);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated gid restriction")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->auth_gid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the length of auxiliary data.
     */
    n = sizeof (m1->data_len);
    assert (n == 4);
    if (n > len) {
        return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
            strdup ("Truncated credential data length")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m1->data_len = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the auxiliary data (if present).
     */
    if (m1->data_len > 0) {
        if (m1->data_len > len) {
            return (_munge_msg_set_err (c->msg, EMUNGE_BAD_CRED,
                strdup ("Truncated credential data")));
        }
        m1->data = p;                   /* data resides in (inner|outer)_mem */
        p += m1->data_len;
        len -= m1->data_len;
    }
    assert (len == 0);
    return (0);
}


static int
dec_v1_validate_auth (munge_cred_t c)
{
/*  Validates whether the client is authorized to view this credential.
 *  But allow root to decode any credential if so configured.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    if ( (m1->auth_uid != MUNGE_UID_ANY)
      && (m1->auth_uid != m1->client_uid)
      && (! (conf->got_root_auth && (m1->client_uid == 0)))) {
        goto unauthorized;
    }
    if (m1->auth_gid == MUNGE_GID_ANY)
        return (0);
    else if (m1->auth_gid == m1->client_gid)
        return (0);
    else if (gids_is_member (conf->gids, m1->client_uid, m1->auth_gid))
        return (0);

unauthorized:
    return (_munge_msg_set_err (c->msg, EMUNGE_CRED_UNAUTHORIZED,
        strdupf ("Unauthorized credential for client uid=%d gid=%d",
            m1->client_uid, m1->client_gid)));
}


static int
dec_v1_validate_time (munge_cred_t c)
{
/*  Validates whether this credential has been generated within an
 *    acceptable time interval.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    int                  skew;          /* negative clock skew for rewind    */
    time_t               tmin;          /* min decode time_t, else rewound   */
    time_t               tmax;          /* max decode time_t, else expired   */

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;
    /*
     *  Bound the cred's ttl by the configuration's max ttl.
     */
    if (m1->ttl > conf->max_ttl) {
        m1->ttl = conf->max_ttl;
    }
    /*  Even if no clock skew is allowed, allow the cred's timestamp to be
     *    "rewound" by up to 1 second.  Without this, we were seeing an
     *    occasional EMUNGE_CRED_REWOUND in spite of NTP's best efforts.
     */
    skew = (conf->got_clock_skew) ? m1->ttl : 1;
    tmin = m1->time0 - skew;
    tmax = m1->time0 + m1->ttl;
    /*
     *  Check the decode time against the allowable min & max.
     */
    if (m1->time1 < tmin) {
        return (_munge_msg_set_err (c->msg, EMUNGE_CRED_REWOUND, NULL));
    }
    if (m1->time1 > tmax) {
        return (_munge_msg_set_err (c->msg, EMUNGE_CRED_EXPIRED, NULL));
    }
    return (0);
}


static int
dec_v1_validate_replay (munge_cred_t c)
{
/*  Validates whether this credential has been replayed.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    int rc;

    assert (c != NULL);
    assert (c->msg != NULL);
    assert (c->msg->head.version == 1);

    m1 = c->msg->pbody;

    rc = replay_insert (c);

    if (rc == 0) {
        return (0);
    }
    if (rc > 0) {
        return (_munge_msg_set_err (c->msg, EMUNGE_CRED_REPLAYED, NULL));
    }
    if (errno == ENOMEM) {
        return (_munge_msg_set_err (c->msg, EMUNGE_NO_MEMORY, NULL));
    }
    /*  An EPERM error can only happen here if replay_insert() failed
     *    because the replay hash is non-existent.  And that can only
     *    happen if replay_insert() was called after replay_fini().
     *    And that shouldn't happen.
     */
    return (_munge_msg_set_err (c->msg, EMUNGE_SNAFU, NULL));
}
