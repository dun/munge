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
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "auth_recv.h"
#include "base64.h"
#include "cipher.h"
#include "conf.h"
#include "cred.h"
#include "crypto.h"
#include "dec.h"
#include "gids.h"
#include "log.h"
#include "m_msg.h"
#include "mac.h"
#include "munge_defs.h"
#include "random.h"
#include "replay.h"
#include "str.h"
#include "zip.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static int dec_validate_msg (m_msg_t m);
static int dec_timestamp (munge_cred_t c);
static int dec_authenticate (munge_cred_t c);
static int dec_check_retry (munge_cred_t c);
static int dec_unarmor (munge_cred_t c);
static int dec_unpack_outer (munge_cred_t c);
static int dec_decrypt (munge_cred_t c);
static int dec_validate_mac (munge_cred_t c);
static int dec_decompress (munge_cred_t c);
static int dec_unpack_inner (munge_cred_t c);
static int dec_validate_time (munge_cred_t c);
static int dec_validate_auth (munge_cred_t c);
static int dec_validate_replay (munge_cred_t c);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

int
dec_process_msg (m_msg_t m)
{
    munge_cred_t c = NULL;              /* aux data for processing this cred */
    int          rc = -1;               /* return code                       */

    if (dec_validate_msg (m) < 0)
        ;
    else if (!(c = cred_create (m)))
        ;
    else if (dec_timestamp (c) < 0)
        ;
    else if (dec_authenticate (c) < 0)
        ;
    else if (dec_check_retry (c) < 0)
        ;
    else if (dec_unarmor (c) < 0)
        ;
    else if (dec_unpack_outer (c) < 0)
        ;
    else if (dec_decrypt (c) < 0)
        ;
    else if (dec_validate_mac (c) < 0)
        ;
    else if (dec_decompress (c) < 0)
        ;
    else if (dec_unpack_inner (c) < 0)
        ;
    else if (dec_validate_auth (c) < 0)
        ;
    else if (dec_validate_time (c) < 0)
        ;
    else if (dec_validate_replay (c) < 0)
        ;
    else /* success */
        rc = 0;

    /*  Since the same m_msg struct is used for both the request and response,
     *    the response message data must be sanitized for most errors.
     *  The exception to this is for a credential that has been successfully
     *    decoded but is invalid due to being expired, rewound, or replayed.
     */
    if ((rc != 0)
            && (m->error_num != EMUNGE_CRED_EXPIRED)
            && (m->error_num != EMUNGE_CRED_REWOUND)
            && (m->error_num != EMUNGE_CRED_REPLAYED) ) {
        m_msg_reset (m);
    }
    /*  If the successfully decoded credential isn't successfully returned to
     *    the client, remove it from the replay hash.
     *
     *  If two instances of the same credential are being decoded at the same
     *    time, dec_validate_replay() will mark the "first" as successful, and
     *    the "second" as replayed.  But if the successful response to the
     *    "first" client fails, that credential will then be marked as
     *    "unplayed", and the replayed reponse to the "second" client will now
     *    be in error.
     */
    if (m_msg_send (m, MUNGE_MSG_DEC_RSP, 0) != EMUNGE_SUCCESS) {
        if (rc == 0) {
            replay_remove (c);
        }
        rc = -1;
    }
    cred_destroy (c);
    return (rc);
}


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static int
dec_validate_msg (m_msg_t m)
{
/*  Validates a credential exists for decoding.
 */
    assert (m != NULL);
    assert (m->type == MUNGE_MSG_DEC_REQ);

    if ((m->data_len == 0) || (m->data == NULL)) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdup ("No credential specified in decode request")));
    }
    return (0);
}


static int
dec_timestamp (munge_cred_t c)
{
/*  Queries the current time.
 */
    m_msg_t  m = c->msg;
    time_t   now;

    /*  Set the "decode" time.
     */
    if (time (&now) == ((time_t) -1)) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdup ("Failed to query current time")));
    }
    m->time0 = 0;
    m->time1 = now;                     /* potential 64b value for 32b var */
    return (0);
}


static int
dec_authenticate (munge_cred_t c)
{
/*  Ascertains the UID/GID of the client process.
 */
    m_msg_t  m = c->msg;
    uid_t   *p_uid;
    gid_t   *p_gid;

    p_uid = (uid_t *) &(m->client_uid);
    p_gid = (gid_t *) &(m->client_gid);

    /*  Determine identity of client process.
     */
    if (auth_recv (m, p_uid, p_gid) != EMUNGE_SUCCESS) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdup ("Failed to determine client identity")));
    }
    return (0);
}


static int
dec_check_retry (munge_cred_t c)
{
/*  Checks whether the transaction is being retried.
 */
    m_msg_t  m = c->msg;

    if (m->retry > 0) {
        log_msg (LOG_INFO,
            "Decode retry #%d for client UID=%u GID=%u", m->retry,
            (unsigned int) m->client_uid, (unsigned int) m->client_gid);
    }
    if (m->retry > MUNGE_SOCKET_RETRY_ATTEMPTS) {
        return (m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Exceeded maximum number of decode attempts")));
    }
    return (0);
}


static int
dec_unarmor (munge_cred_t c)
{
/*  Removes the credential's armor, converting it into a packed byte array.
 *  The armor consists of PREFIX + BASE64 [ OUTER + MAC + INNER ] + SUFFIX.
 */
    m_msg_t        m = c->msg;
    int            prefix_len;          /* prefix string length              */
    int            suffix_len;          /* prefix string length              */
    int            base64_len;          /* length of base64 data             */
    unsigned char *base64_ptr;          /* base64 data (ptr into msg data)   */
    unsigned char *base64_tmp;          /* base64 data tmp ptr               */
    int            n;                   /* all-purpose int                   */

    prefix_len = strlen (MUNGE_CRED_PREFIX);
    suffix_len = strlen (MUNGE_CRED_SUFFIX);

    base64_ptr = m->data;
    base64_len = m->data_len;

    /*  Consume leading whitespace.
     */
    while ((base64_len > 0) && isspace (*base64_ptr)) {
        base64_ptr++;
        base64_len--;
    }
    if ((base64_len == 0) || (*base64_ptr == '\0')) {
        return (m_msg_set_err (m, EMUNGE_BAD_ARG,
            strdup ("No credential specified")));
    }
    /*  Remove the prefix string.
     *  The prefix specifies the start of the base64-encoded data.
     */
    if (prefix_len > 0) {
        if (strncmp ((char *) base64_ptr, MUNGE_CRED_PREFIX, prefix_len)) {
            return (m_msg_set_err (m, EMUNGE_BAD_CRED,
                strdup ("Failed to match armor prefix")));
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
            return (m_msg_set_err (m, EMUNGE_BAD_CRED,
                strdup ("Failed to match armor suffix")));
        }
        base64_len = base64_tmp - base64_ptr;
    }
    /*  Allocate memory for unarmor'd data.
     */
    c->outer_mem_len = base64_decode_length (base64_len);
    if (!(c->outer_mem = malloc (c->outer_mem_len))) {
        return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
    }
    /*  Base64-decode the chewy-internals of the credential.
     */
    if (base64_decode_block (c->outer_mem, &n, base64_ptr, base64_len) < 0) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Failed to base64-decode credential")));
    }
    assert (n < c->outer_mem_len);

    /*  Now that the "request data" has been unarmored, it can be free()d.
     */
    free (m->data);
    m->data = NULL;
    m->data_len = 0;
    assert (m->data_is_copy == 0);

    /*  Note outer_len is an upper bound which will be refined when unpacked.
     *  It currently includes OUTER + MAC + INNER.
     */
    c->outer = c->outer_mem;
    c->outer_len = n;
    return (0);
}


static int
dec_unpack_outer (munge_cred_t c)
{
/*  Unpacks the "outer" credential data from MSBF (ie, big endian) format.
 *  The "outer" part of the credential does not undergo cryptographic
 *    transformations (ie, compression and encryption).  It includes:
 *    cred version, cipher type, mac type, compression type, realm length,
 *    unterminated realm string (if realm_len > 0), and the cipher's
 *    initialization vector (if encrypted).
 *  Validation of the "outer" credential occurs here as well since unpacking
 *    may not be able to continue if an invalid field is found.
 *  While the MAC is not technically part of the "outer" credential data,
 *    it is unpacked here since it resides in outer_mem and its location
 *    (along with the location of the "inner" data) is determined as a
 *    result of unpacking the "outer" data.
 */
    m_msg_t           m = c->msg;
    unsigned char    *p;                /* ptr into packed data              */
    int               len;              /* length of packed data remaining   */
    int               n;                /* all-purpose int                   */

    assert (c->outer != NULL);

    /*  Initialize.
     */
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
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated credential version")));
    }
    c->version = *p;
    if (c->version != MUNGE_CRED_VERSION) {
        return (m_msg_set_err (m, EMUNGE_BAD_VERSION,
            strdupf ("Invalid credential version %d", c->version)));
    }
    p += n;
    len -= n;
    /*
     *  Unpack the cipher type.
     */
    n = sizeof (m->cipher);
    assert (n == 1);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated cipher type")));
    }
    m->cipher = *p;
    if (m->cipher == MUNGE_CIPHER_NONE) {
        c->iv_len = 0;
    }
    else {
        if (cipher_map_enum (m->cipher, NULL) < 0) {
            return (m_msg_set_err (m, EMUNGE_BAD_CIPHER,
                strdupf ("Invalid cipher type %d", m->cipher)));
        }
        c->iv_len = cipher_iv_size (m->cipher);
        if (c->iv_len < 0) {
            return (m_msg_set_err (m, EMUNGE_SNAFU,
                strdupf ("Failed to determine IV length for cipher type %d",
                m->cipher)));
        }
        assert (c->iv_len <= sizeof (c->iv));
    }
    p += n;
    len -= n;
    /*
     *  Unpack the message authentication code type.
     */
    n = sizeof (m->mac);
    assert (n == 1);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated MAC type")));
    }
    m->mac = *p;
    if (mac_map_enum (m->mac, NULL) < 0) {
        return (m_msg_set_err (m, EMUNGE_BAD_MAC,
            strdupf ("Invalid MAC type %d", m->mac)));
    }
    c->mac_len = mac_size (m->mac);
    if (c->mac_len <= 0) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Failed to determine digest length for MAC type %d",
            m->mac)));
    }
    assert (c->mac_len <= sizeof (c->mac));
    p += n;
    len -= n;
    /*
     *  Validate the message authentication code type against the cipher type
     *    to ensure the HMAC will generate a DEK of sufficient length for the
     *    cipher.
     */
    if (mac_size (m->mac) < cipher_key_size (m->cipher)) {
        return (m_msg_set_err (m, EMUNGE_BAD_MAC,
            strdupf ("Invalid MAC type %d with cipher type %d",
            m->mac, m->cipher)));
    }
    /*
     *  Unpack the compression type.
     */
    n = sizeof (m->zip);
    assert (n == 1);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated compression type")));
    }
    m->zip = *p;
    if (m->zip == MUNGE_ZIP_NONE) {
        ; /* not compressed */
    }
    else {
        if (!zip_is_valid_type (m->zip)) {
            return (m_msg_set_err (m, EMUNGE_BAD_ZIP,
                strdupf ("Invalid compression type %d", m->zip)));
        }
    }
    p += n;
    len -= n;
    /*
     *  Unpack the length of realm string.
     */
    n = sizeof (m->realm_len);
    assert (n == 1);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated security realm length")));
    }
    m->realm_len = *p;
    p += n;
    len -= n;
    /*
     *  Unpack the unterminated realm string (if present).
     *    Note that the realm string is NUL-terminated after unpacking.
     */
    if (m->realm_len > 0) {
        if (m->realm_len > len) {
            return (m_msg_set_err (m, EMUNGE_BAD_CRED,
                strdup ("Truncated security realm string")));
        }
        c->realm_mem_len = m->realm_len + 1;
        /*
         *  Since the realm len is a uint8, the max memory malloc'd here
         *    for the realm string is 256 bytes.
         */
        if (!(c->realm_mem = malloc (c->realm_mem_len))) {
            return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
        }
        memcpy (c->realm_mem, p, m->realm_len);
        c->realm_mem[m->realm_len] = '\0';
        p += m->realm_len;
        len -= m->realm_len;
        /*
         *  Update realm & realm_len to refer to the string in "cred memory".
         */
        m->realm_str = (char *) c->realm_mem;
        m->realm_len = c->realm_mem_len;
        m->realm_is_copy = 1;
    }
    /*  Unpack the cipher initialization vector (if needed).
     *    The length of the IV was derived from the cipher type.
     */
    if (c->iv_len > 0) {
        if (c->iv_len > len) {
            return (m_msg_set_err (m, EMUNGE_BAD_CRED,
                strdup ("Truncated cipher IV")));
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
    return (0);
}


static int
dec_decrypt (munge_cred_t c)
{
/*  Decrypts the "inner" credential data.
 *
 *  Note that if cipher_final() fails, an error condition is set but an error
 *    status is not returned (yet).  Here's why:
 *  cipher_final() will return an error code during decryption if padding is
 *    enabled and the final block is not correctly formatted.
 *  If block cipher padding errors are not treated the same as MAC verification
 *    errors, an attacker may be able to launch Vaudenay's attack on padding:
 *    - <http://lasecwww.epfl.ch/php_code/publications/search.php?ref=Vau01>
 *    - <http://lasecwww.epfl.ch/php_code/publications/search.php?ref=Vau02a>
 *    - <http://lasecwww.epfl.ch/memo_ssl.shtml>
 *    - <http://www.openssl.org/~bodo/tls-cbc.txt>
 *  Consequently, if cipher_final() returns a failure, the error condition is
 *    set here and the MAC computation in dec_validate_mac() is performed
 *    regardless in order to minimize information leaked via timing.
 */
    m_msg_t           m = c->msg;
    int               buf_len;          /* length of plaintext buffer        */
    unsigned char    *buf;              /* plaintext buffer                  */
    unsigned char    *buf_ptr;          /* ptr into plaintext buffer         */
    cipher_ctx        x;                /* cipher context                    */
    int               n_written;        /* number of bytes written to buf    */
    int               n;                /* all-purpose int                   */

    /*  Is this credential encrypted?
     */
    if (m->cipher == MUNGE_CIPHER_NONE) {
        return (0);
    }
    /*  Compute DEK.
     *  msg-dek = MAC (msg-mac) using DEK subkey
     */
    c->dek_len = mac_size (m->mac);
    if (c->dek_len <= 0) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Failed to determine DEK key length for MAC type %d",
                m->mac)));
    }
    assert (c->dek_len <= sizeof (c->dek));

    n = c->dek_len;
    if (mac_block (m->mac, conf->dek_key, conf->dek_key_len,
            c->dek, &n, c->mac, c->mac_len) < 0) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdup ("Failed to compute DEK")));
    }
    assert (n <= c->dek_len);
    assert (n >= cipher_key_size (m->cipher));

    /*  Allocate memory for plaintext.
     *  Ensure enough space by allocating an additional cipher block.
     */
    n = cipher_block_size (m->cipher);
    if (n <= 0) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Failed to determine block size for cipher type %d",
                m->cipher)));
    }
    buf_len = c->inner_len + n;
    if (!(buf = malloc (buf_len))) {
        return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
    }
    /*  Decrypt "inner" data.
     */
    if (cipher_init (&x, m->cipher, c->dek, c->iv, CIPHER_DECRYPT) < 0) {
        goto err;
    }
    buf_ptr = buf;
    n_written = 0;
    n = buf_len;
    if (cipher_update (&x, buf_ptr, &n, c->inner, c->inner_len) < 0) {
        goto err_cleanup;
    }
    buf_ptr += n;
    n_written += n;
    n = buf_len - n_written;
    if (cipher_final (&x, buf_ptr, &n) < 0) {
        /*  Set but defer error until dec_validate_mac().  */
        m_msg_set_err (m, EMUNGE_CRED_INVALID, NULL);
    }
    buf_ptr += n;
    n_written += n;
    if (cipher_cleanup (&x) < 0) {
        goto err;
    }
    assert (n_written <= buf_len);

    /*  Replace "inner" ciphertext with plaintext.
     */
    assert (c->inner_mem == NULL);
    assert (c->inner_mem_len == 0);
    c->inner_mem = buf;
    c->inner_mem_len = buf_len;
    c->inner = buf;
    c->inner_len = n_written;
    return (0);

err_cleanup:
    cipher_cleanup (&x);
err:
    memset (buf, 0, buf_len);
    free (buf);
    return (m_msg_set_err (m, EMUNGE_SNAFU,
        strdup ("Failed to decrypt credential")));
}


static int
dec_validate_mac (munge_cred_t c)
{
/*  Validates the Message Authentication Code (MAC) over the entire message
 *    (ie, both "outer" and "inner" data).
 */
    m_msg_t        m = c->msg;
    mac_ctx        x;                   /* message auth code context         */
    unsigned char  mac[MAX_MAC];        /* message authentication code       */
    int            n;                   /* all-purpose int                   */

    /*  Compute MAC.
     */
    if (mac_init (&x, m->mac, conf->mac_key, conf->mac_key_len) < 0) {
        goto err;
    }
    if (mac_update (&x, c->outer, c->outer_len) < 0) {
        goto err_cleanup;
    }
    if (mac_update (&x, c->inner, c->inner_len) < 0) {
        goto err_cleanup;
    }
    n = sizeof (mac);
    if (mac_final (&x, mac, &n) < 0) {
        goto err_cleanup;
    }
    if (mac_cleanup (&x) < 0) {
        goto err;
    }
    assert (n <= sizeof (mac));

    /*  Validate new computed MAC against old received MAC.
     */
    if ((n != c->mac_len) || (crypto_memcmp (mac, c->mac, c->mac_len) != 0)) {
        return (m_msg_set_err (m, EMUNGE_CRED_INVALID, NULL));
    }
    /*  Ensure an invalid cred error from before is caught
     *    (if it wasn't somehow already caught by the MAC validation).
     */
    if (m->error_num != EMUNGE_SUCCESS) {
        return (-1);
    }
    return (0);

err_cleanup:
    mac_cleanup (&x);
err:
    return (m_msg_set_err (m, EMUNGE_SNAFU,
        strdup ("Failed to MAC credential")));
}


static int
dec_decompress (munge_cred_t c)
{
/*  Decompresses the "inner" credential data.
 */
    m_msg_t        m = c->msg;
    unsigned char *buf;                 /* decompression buffer              */
    int            buf_len;             /* length of decompression buffer    */
    int            n;                   /* length of decompressed data       */

    /*  Is this credential compressed?
     */
    if (m->zip == MUNGE_ZIP_NONE) {
        return (0);
    }
    /*  Compression type already checked by dec_unpack_outer().
     */
    assert (zip_is_valid_type (m->zip));
    /*
     *  Allocate memory for decompressed "inner" data.
     */
    buf = NULL;
    buf_len = zip_decompress_length (m->zip, c->inner, c->inner_len);
    if (buf_len <= 0) {
        goto err;
    }
    if (!(buf = malloc (buf_len))) {
        m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL);
        goto err;
    }
    /*  Decompress "inner" data.
     */
    n = buf_len;
    if (zip_decompress_block (m->zip, buf, &n, c->inner, c->inner_len) < 0) {
        return (m_msg_set_err (m, EMUNGE_CRED_INVALID, NULL));
    }
    assert (n == buf_len);
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
    return (m_msg_set_err (m, EMUNGE_SNAFU,
        strdup ("Failed to decompress credential")));
}


static int
dec_unpack_inner (munge_cred_t c)
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
    m_msg_t        m = c->msg;
    unsigned char *p;                   /* ptr into packed data              */
    int            len;                 /* length of packed data remaining   */
    int            n;                   /* all-purpose int                   */
    uint32_t       u;                   /* all-purpose uint32                */

    assert (c->inner != NULL);

    /*  Initialize.
     */
    p = c->inner;
    len = c->inner_len;
    /*
     *  Unpack the salt.
     *  Add it to the PRNG entropy pool if it's encrypted.
     */
    c->salt_len = MUNGE_CRED_SALT_LEN;
    assert (c->salt_len <= sizeof (c->salt));
    if (c->salt_len > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated salt")));
    }
    memcpy (c->salt, p, c->salt_len);
    if (m->cipher != MUNGE_CIPHER_NONE) {
        random_add (c->salt, c->salt_len);
    }
    p += c->salt_len;
    len -= c->salt_len;
    /*
     *  Unpack the length of the origin IP address.
     */
    n = sizeof (m->addr_len);
    assert (n == 1);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated origin IP addr length")));
    }
    m->addr_len = *p;                   /* a single byte is always aligned */
    p += n;
    len -= n;
    /*
     *  Unpack the origin IP address.
     */
    if (m->addr_len > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated origin IP addr")));
    }
    else if (m->addr_len == 4) {
        assert (sizeof (m->addr) == 4);
        memcpy (&m->addr, p, m->addr_len);
    }
    else if (m->addr_len == 0) {
        memset (&m->addr, 0, sizeof (m->addr));
    }
    else {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Invalid origin IP addr length")));
    }
    p += m->addr_len;
    len -= m->addr_len;
    /*
     *  Unpack the encode time.
     */
    n = sizeof (m->time0);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated encode time")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->time0 = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the time-to-live.
     */
    n = sizeof (m->ttl);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated time-to-live")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->ttl = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the UID.
     */
    n = sizeof (m->cred_uid);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated UID")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->cred_uid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the GID.
     */
    n = sizeof (m->cred_gid);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated GID")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->cred_gid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the UID restriction for authorization.
     */
    n = sizeof (m->auth_uid);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated UID restriction")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->auth_uid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the GID restriction for authorization.
     */
    n = sizeof (m->auth_gid);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated GID restriction")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->auth_gid = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the length of auxiliary data.
     */
    n = sizeof (m->data_len);
    assert (n == 4);
    if (n > len) {
        return (m_msg_set_err (m, EMUNGE_BAD_CRED,
            strdup ("Truncated data length")));
    }
    memcpy (&u, p, n);                  /* ensure proper byte-alignment */
    m->data_len = ntohl (u);
    p += n;
    len -= n;
    /*
     *  Unpack the auxiliary data (if present).
     *  The 'data' memory is owned by the cred struct, so it will be
     *    free()d by cred_destroy() called from dec_process_msg().
     */
    if (m->data_len > 0) {
        if (m->data_len > len) {
            return (m_msg_set_err (m, EMUNGE_BAD_CRED,
                strdup ("Truncated data")));
        }
        m->data = p;                    /* data resides in (inner|outer)_mem */
        p += m->data_len;
        len -= m->data_len;
        m->data_is_copy = 1;
    }
    else {
        m->data = NULL;
    }
    assert (len == 0);
    return (0);
}


static int
dec_validate_auth (munge_cred_t c)
{
/*  Validates whether the client is authorized to view this credential.
 *  But allow root to decode any credential if so configured.
 */
    m_msg_t  m = c->msg;

    if ( (m->auth_uid != MUNGE_UID_ANY)
      && (m->auth_uid != m->client_uid)
      && (! (conf->got_root_auth && (m->client_uid == 0)))) {
        goto unauthorized;
    }
    if (m->auth_gid == MUNGE_GID_ANY) {
        return (0);
    }
    else if (m->auth_gid == m->client_gid) {
        return (0);
    }
    else if (gids_is_member (conf->gids, m->client_uid, m->auth_gid)) {
        return (0);
    }

unauthorized:
    return (m_msg_set_err (m, EMUNGE_CRED_UNAUTHORIZED,
        strdupf ("Unauthorized credential for client UID=%u GID=%u",
            (unsigned int) m->client_uid, (unsigned int) m->client_gid)));
}


static int
dec_validate_time (munge_cred_t c)
{
/*  Validates whether this credential has been generated within an
 *    acceptable time interval.
 */
    m_msg_t  m = c->msg;
    int      skew;                      /* negative clock skew for rewind    */
    time_t   tmin;                      /* min decode time_t, else rewound   */
    time_t   tmax;                      /* max decode time_t, else expired   */

    /*  Bound the cred's ttl by the configuration's max ttl.
     */
    if (m->ttl > conf->max_ttl) {
        m->ttl = conf->max_ttl;
    }
    /*  Even if no clock skew is allowed, allow the cred's timestamp to be
     *    "rewound" by up to 1 second.  Without this, we were seeing an
     *    occasional EMUNGE_CRED_REWOUND in spite of NTP's best efforts.
     */
    skew = (conf->got_clock_skew) ? m->ttl : 1;
    tmin = m->time0 - skew;
    tmax = m->time0 + m->ttl;
    /*
     *  Check the decode time against the allowable min & max.
     */
    if (m->time1 < tmin) {
        return (m_msg_set_err (m, EMUNGE_CRED_REWOUND, NULL));
    }
    if (m->time1 > tmax) {
        return (m_msg_set_err (m, EMUNGE_CRED_EXPIRED, NULL));
    }
    return (0);
}


static int
dec_validate_replay (munge_cred_t c)
{
/*  Validates whether this credential has been replayed.
 */
    m_msg_t  m = c->msg;
    int      rc;

    rc = replay_insert (c);

    if (rc == 0) {
        return (0);
    }
    if (rc > 0) {
        if ((conf->got_socket_retry)
                && (m->retry > 0)
                && (m->retry <= MUNGE_SOCKET_RETRY_ATTEMPTS)) {
            log_msg (LOG_INFO,
                "Allowed credential replay for client UID=%u GID=%u",
                (unsigned int) m->client_uid, (unsigned int) m->client_gid);
            return (0);
        }
        else {
            return (m_msg_set_err (m, EMUNGE_CRED_REPLAYED, NULL));
        }
    }
    if (errno == ENOMEM) {
        return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
    }
    /*  An EPERM error can only happen here if replay_insert() failed
     *    because the replay hash is non-existent.  And that can only
     *    happen if replay_insert() was called after replay_fini().
     *    And that shouldn't happen.
     */
    return (m_msg_set_err (m, EMUNGE_SNAFU, NULL));
}
