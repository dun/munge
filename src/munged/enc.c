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
#include "enc.h"
#include "log.h"
#include "m_msg.h"
#include "mac.h"
#include "munge_defs.h"
#include "random.h"
#include "str.h"
#include "zip.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static int enc_validate_msg (m_msg_t m);
static int enc_init (munge_cred_t c);
static int enc_authenticate (munge_cred_t c);
static int enc_check_retry (munge_cred_t c);
static int enc_timestamp (munge_cred_t c);
static int enc_pack_outer (munge_cred_t c);
static int enc_pack_inner (munge_cred_t c);
static int enc_compress (munge_cred_t c);
static int enc_mac (munge_cred_t c);
static int enc_encrypt (munge_cred_t c);
static int enc_armor (munge_cred_t c);
static int enc_fini (munge_cred_t c);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

int
enc_process_msg (m_msg_t m)
{
    munge_cred_t c = NULL;              /* aux data for processing this cred */
    int          rc = -1;               /* return code                       */

    if (enc_validate_msg (m) < 0)
        ;
    else if (!(c = cred_create (m)))
        ;
    else if (enc_init (c) < 0)
        ;
    else if (enc_authenticate (c) < 0)
        ;
    else if (enc_check_retry (c) < 0)
        ;
    else if (enc_timestamp (c) < 0)
        ;
    else if (enc_pack_outer (c) < 0)
        ;
    else if (enc_pack_inner (c) < 0)
        ;
    else if (enc_compress (c) < 0)
        ;
    else if (enc_mac (c) < 0)
        ;
    else if (enc_encrypt (c) < 0)
        ;
    else if (enc_armor (c) < 0)
        ;
    else if (enc_fini (c) < 0)
        ;
    else /* success */
        rc = 0;

    /*  Since the same m_msg struct is used for both the request and response,
     *    the response message data must be sanitized for most errors.
     */
    if (rc != 0) {
        m_msg_reset (m);
    }
    if (m_msg_send (m, MUNGE_MSG_ENC_RSP, 0) != EMUNGE_SUCCESS) {
        rc = -1;
    }
    cred_destroy (c);
    return (rc);
}


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static int
enc_validate_msg (m_msg_t m)
{
/*  Validates message types, setting defaults and limits as needed.
 */
    assert (m != NULL);
    assert (m->type == MUNGE_MSG_ENC_REQ);

    /*  Validate cipher type.
     */
    if (m->cipher == MUNGE_CIPHER_DEFAULT) {
        m->cipher = conf->def_cipher;
    }
    else if (m->cipher == MUNGE_CIPHER_NONE) {
        ; /* disable encryption */
    }
    else if (cipher_map_enum (m->cipher, NULL) < 0) {
        return (m_msg_set_err (m, EMUNGE_BAD_CIPHER,
            strdupf ("Invalid cipher type %d", m->cipher)));
    }
    /*  Validate message authentication code type.
     *  Note that MUNGE_MAC_NONE is not valid -- MACs are REQUIRED!
     */
    if (m->mac == MUNGE_MAC_DEFAULT) {
        m->mac = conf->def_mac;
    }
    else if (mac_map_enum (m->mac, NULL) < 0) {
        return (m_msg_set_err (m, EMUNGE_BAD_MAC,
            strdupf ("Invalid MAC type %d", m->mac)));
    }
    assert (m->mac != MUNGE_MAC_NONE);
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
    /*  Validate compression type.
     *  Disable compression if no optional data was specified.
     */
    if (m->zip == MUNGE_ZIP_DEFAULT) {
        m->zip = conf->def_zip;
    }
    else if (m->zip == MUNGE_ZIP_NONE) {
        ; /* disable compression */
    }
    else if (!zip_is_valid_type (m->zip)) {
        return (m_msg_set_err (m, EMUNGE_BAD_ZIP,
            strdupf ("Invalid compression type %d", m->zip)));
    }
    if (m->data_len == 0) {
        m->zip = MUNGE_ZIP_NONE;
    }
    /*  Validate realm.
     *
     *  FIXME: Validate realm and set default string if needed.
     *         Validate that the realm string is NUL-terminated.
     */
    /*  Validate time-to-live.
     *  Ensure it is bounded by the configuration's max ttl.
     *    A sensible ttl is needed to allow a validated cred's
     *    state to be flushed from the replay hash at some point.
     */
    if (m->ttl == 0) {
        m->ttl = conf->def_ttl;
    }
    else if (m->ttl > conf->max_ttl) {
        m->ttl = conf->max_ttl;
    }
    return (0);
}


static int
enc_init (munge_cred_t c)
{
/*  Initializes state necessary for encoding a credential.
 */
    m_msg_t  m = c->msg;

    /*  Generate salt.
     */
    c->salt_len = MUNGE_CRED_SALT_LEN;
    random_pseudo_bytes (c->salt, c->salt_len);

    /*  Generate cipher initialization vector (if needed).
     */
    if (m->cipher == MUNGE_CIPHER_NONE) {
        c->iv_len = 0;
    }
    else {
        c->iv_len = cipher_iv_size (m->cipher);
        if (c->iv_len < 0) {
            return (m_msg_set_err (m, EMUNGE_SNAFU,
                strdupf ("Failed to determine IV length for cipher type %d",
                m->cipher)));
        }
        if (c->iv_len > 0) {
            assert (c->iv_len <= sizeof (c->iv));
            random_pseudo_bytes (c->iv, c->iv_len);
        }
    }
    return (0);
}


static int
enc_authenticate (munge_cred_t c)
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
enc_check_retry (munge_cred_t c)
{
/*  Checks whether the transaction is being retried.
 */
    m_msg_t  m = c->msg;

    if (m->retry > 0) {
        log_msg (LOG_INFO,
            "Encode retry #%d for client UID=%u GID=%u", m->retry,
            (unsigned int) m->client_uid, (unsigned int) m->client_gid);
    }
    if (m->retry > MUNGE_SOCKET_RETRY_ATTEMPTS) {
        return (m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Exceeded maximum number of encode attempts")));
    }
    return (0);
}


static int
enc_timestamp (munge_cred_t c)
{
/*  Queries the current time.
 */
    m_msg_t  m = c->msg;
    time_t   now;

    /*  Set the "encode" time.
     */
    if (time (&now) == ((time_t) -1)) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdup ("Failed to query current time")));
    }
    m->time0 = now;                     /* potential 64b value for 32b var */
    m->time1 = 0;
    return (0);
}


static int
enc_pack_outer (munge_cred_t c)
{
/*  Packs the "outer" credential data into MSBF (ie, big endian) format.
 *  The "outer" part of the credential does not undergo cryptographic
 *    transformations (ie, compression and encryption).  It includes:
 *    cred version, cipher type, mac type, compression type, realm length,
 *    unterminated realm string (if realm_len > 0), and the cipher's
 *    initialization vector (if encrypted).
 */
    m_msg_t        m = c->msg;
    unsigned char *p;                   /* ptr into packed data              */

    assert (c->outer_mem == NULL);

    c->outer_mem_len += sizeof (c->version);
    c->outer_mem_len += sizeof (m->cipher);
    c->outer_mem_len += sizeof (m->mac);
    c->outer_mem_len += sizeof (m->zip);
    c->outer_mem_len += sizeof (m->realm_len);
    c->outer_mem_len += m->realm_len;
    c->outer_mem_len += c->iv_len;
    if (!(c->outer_mem = malloc (c->outer_mem_len))) {
        return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
    }
    p = c->outer = c->outer_mem;
    c->outer_len = c->outer_mem_len;

    assert (sizeof (c->version) == 1);
    *p = c->version;
    p += sizeof (c->version);

    assert (sizeof (m->cipher) == 1);
    *p = m->cipher;
    p += sizeof (m->cipher);

    assert (sizeof (m->mac) == 1);
    *p = m->mac;
    p += sizeof (m->mac);

    assert (sizeof (m->zip) == 1);
    c->outer_zip_ref = p;
    *p = m->zip;
    p += sizeof (m->zip);

    assert (sizeof (m->realm_len) == 1);
    *p = m->realm_len;
    p += sizeof (m->realm_len);

    if (m->realm_len > 0) {
        memcpy (p, m->realm_str, m->realm_len);
        p += m->realm_len;
    }
    if (c->iv_len > 0) {
        memcpy (p, c->iv, c->iv_len);
        p += c->iv_len;
    }
    assert (p == (c->outer + c->outer_len));
    return (0);
}


static int
enc_pack_inner (munge_cred_t c)
{
/*  Packs the "inner" credential data into MSBF (ie, big endian) format.
 *  The "inner" part of the credential may be subjected to cryptographic
 *    transformations (ie, compression and encryption).  It includes:
 *    salt, ip addr len, origin ip addr, encode time, ttl, uid, gid,
 *    data length, and data (if present).
 */
    m_msg_t        m = c->msg;
    unsigned char *p;                   /* ptr into packed data              */
    uint32_t       u32;                 /* tmp for packing into MSBF         */

    assert (c->inner_mem == NULL);

    c->inner_mem_len += c->salt_len;
    c->inner_mem_len += sizeof (m->addr_len);
    c->inner_mem_len += sizeof (m->addr);
    c->inner_mem_len += sizeof (m->time0);
    c->inner_mem_len += sizeof (m->ttl);
    c->inner_mem_len += sizeof (m->client_uid);
    c->inner_mem_len += sizeof (m->client_gid);
    c->inner_mem_len += sizeof (m->auth_uid);
    c->inner_mem_len += sizeof (m->auth_gid);
    c->inner_mem_len += sizeof (m->data_len);
    c->inner_mem_len += m->data_len;
    if (!(c->inner_mem = malloc (c->inner_mem_len))) {
        return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
    }
    p = c->inner = c->inner_mem;
    c->inner_len = c->inner_mem_len;

    assert (c->salt_len > 0);
    memcpy (p, c->salt, c->salt_len);
    p += c->salt_len;

    assert (sizeof (m->addr_len) == 1);
    assert (sizeof (conf->addr) == sizeof (m->addr));
    assert (sizeof (conf->addr) < 256);
    *p = m->addr_len = sizeof (m->addr);
    p += sizeof (m->addr_len);
    memcpy (p, &conf->addr, sizeof (m->addr));
    p += sizeof (m->addr);

    assert (sizeof (m->time0) == 4);
    u32 = htonl (m->time0);
    memcpy (p, &u32, sizeof (m->time0));
    p += sizeof (m->time0);

    assert (sizeof (m->ttl) == 4);
    u32 = htonl (m->ttl);
    memcpy (p, &u32, sizeof (m->ttl));
    p += sizeof (m->ttl);

    assert (sizeof (m->client_uid) == 4);
    u32 = htonl (m->client_uid);
    memcpy (p, &u32, sizeof (m->client_uid));
    p += sizeof (m->client_uid);

    assert (sizeof (m->client_gid) == 4);
    u32 = htonl (m->client_gid);
    memcpy (p, &u32, sizeof (m->client_gid));
    p += sizeof (m->client_gid);

    assert (sizeof (m->auth_uid) == 4);
    u32 = htonl (m->auth_uid);
    memcpy (p, &u32, sizeof (m->auth_uid));
    p += sizeof (m->auth_uid);

    assert (sizeof (m->auth_gid) == 4);
    u32 = htonl (m->auth_gid);
    memcpy (p, &u32, sizeof (m->auth_gid));
    p += sizeof (m->auth_gid);

    assert (sizeof (m->data_len) == 4);
    u32 = htonl (m->data_len);
    memcpy (p, &u32, sizeof (m->data_len));
    p += sizeof (m->data_len);

    if (m->data_len > 0) {
        memcpy (p, m->data, m->data_len);
        p += m->data_len;
    }
    assert (p == (c->inner + c->inner_len));
    return (0);
}


static int
enc_compress (munge_cred_t c)
{
/*  Compresses the "inner" credential data.
 *  If the compressed data is larger than the original data, the
 *    compressed buffer is discarded and compression is disabled.
 *    This requires resetting the compression type in the credential's
 *    "outer" data header.  And since that field is included in the MAC,
 *    compression must be attempted before the MAC is computed.
 */
    m_msg_t        m = c->msg;
    unsigned char *buf;                 /* compression buffer                */
    int            buf_len;             /* length of compression buffer      */
    int            n;                   /* length of compressed data         */

    /*  Is compression disabled?
     */
    if (m->zip == MUNGE_ZIP_NONE) {
        return (0);
    }
    /*  Allocate memory for compressed "inner" data.
     */
    buf = NULL;
    buf_len = zip_compress_length (m->zip, c->inner, c->inner_len);
    if (buf_len < 0) {
        goto err;
    }
    if (!(buf = malloc (buf_len))) {
        m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL);
        goto err;
    }
    /*  Compress "inner" data.
     */
    n = buf_len;
    if (zip_compress_block (m->zip, buf, &n, c->inner, c->inner_len) < 0) {
        goto err;
    }
    /*  Disable compression and discard compressed data if it's larger.
     *    Replace "inner" data with compressed data if it's not.
     */
    if (n >= c->inner_len) {
        m->zip = MUNGE_ZIP_NONE;
        *c->outer_zip_ref = m->zip;
        memset (buf, 0, buf_len);
        free (buf);
    }
    else {
        assert (c->inner_mem_len > 0);
        memset (c->inner_mem, 0, c->inner_mem_len);
        free (c->inner_mem);

        c->inner_mem = buf;
        c->inner_mem_len = buf_len;
        c->inner = buf;
        c->inner_len = n;
    }
    return (0);

err:
    if ((buf_len > 0) && (buf != NULL)) {
        memset (buf, 0, buf_len);
        free (buf);
    }
    return (m_msg_set_err (m, EMUNGE_SNAFU,
        strdup ("Failed to compress credential")));
}


static int
enc_mac (munge_cred_t c)
{
/*  Computes the Message Authentication Code (MAC) over the entire message
 *    (ie, both "outer" and "inner" data).
 */
    m_msg_t       m = c->msg;
    mac_ctx       x;                    /* message auth code context         */
    int           n;                    /* all-purpose int                   */

    /*  Init MAC.
     */
    c->mac_len = mac_size (m->mac);
    if (c->mac_len <= 0) {
        return (m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Failed to determine digest length for MAC type %d",
                m->mac)));
    }
    assert (c->mac_len <= sizeof (c->mac));
    memset (c->mac, 0, c->mac_len);

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
    n = c->mac_len;
    if (mac_final (&x, c->mac, &n) < 0) {
        goto err_cleanup;
    }
    if (mac_cleanup (&x) < 0) {
        goto err;
    }
    assert (n == c->mac_len);
    return (0);

err_cleanup:
    mac_cleanup (&x);
err:
    return (m_msg_set_err (m, EMUNGE_SNAFU,
        strdup ("Failed to MAC credential")));
}


static int
enc_encrypt (munge_cred_t c)
{
/*  Encrypts the "inner" credential data.
 */
    m_msg_t           m = c->msg;
    int               buf_len;          /* length of ciphertext buffer       */
    unsigned char    *buf;              /* ciphertext buffer                 */
    unsigned char    *buf_ptr;          /* ptr into ciphertext buffer        */
    cipher_ctx        x;                /* cipher context                    */
    int               n_written;        /* number of bytes written to buf    */
    int               n;                /* all-purpose int                   */

    /*  Is encryption disabled?
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

    /*  Allocate memory for ciphertext.
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
    /*  Encrypt "inner" data.
     */
    if (cipher_init (&x, m->cipher, c->dek, c->iv, CIPHER_ENCRYPT) < 0) {
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
        goto err_cleanup;
    }
    buf_ptr += n;
    n_written += n;
    if (cipher_cleanup (&x) < 0) {
        goto err;
    }
    assert (n_written <= buf_len);

    /*  Replace "inner" plaintext with ciphertext.
     */
    assert (c->inner_mem_len > 0);
    memset (c->inner_mem, 0, c->inner_mem_len);
    free (c->inner_mem);

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
        strdup ("Failed to encrypt credential")));
}


static int
enc_armor (munge_cred_t c)
{
/*  Armors the credential allowing it to be sent over virtually any transport.
 *  The armor consists of PREFIX + BASE64 [ OUTER + MAC + INNER ] + SUFFIX.
 */
    m_msg_t        m = c->msg;
    int            prefix_len;          /* prefix string length              */
    int            suffix_len;          /* prefix string length              */
    int            buf_len;             /* length of armor'd data buffer     */
    unsigned char *buf;                 /* armor'd data buffer               */
    unsigned char *buf_ptr;             /* ptr into armor'd data buffer      */
    base64_ctx     x;                   /* base64 context                    */
    int            n, n2;               /* all-purpose ints                  */

    prefix_len = strlen (MUNGE_CRED_PREFIX);
    suffix_len = strlen (MUNGE_CRED_SUFFIX);

    /*  Allocate memory for armor'd data.
     */
    n = c->outer_len + c->mac_len + c->inner_len;
    buf_len = prefix_len + base64_encode_length (n) + suffix_len;

    if (!(buf = malloc (buf_len))) {
        return (m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL));
    }
    buf_ptr = buf;

    /*  Add the prefix string.
     */
    if (prefix_len > 0) {
        strcpy ((char *) buf_ptr, MUNGE_CRED_PREFIX); /* strcpy() safe here */
        buf_ptr += prefix_len;
    }
    /*  Base64-encode the chewy-internals of the credential.
     *  The data will be NUL-terminated by in the process.
     */
    if (base64_init (&x) < 0) {
        goto err;
    }
    n = 0;
    if (base64_encode_update (&x, buf_ptr, &n2, c->outer, c->outer_len) < 0) {
        goto err_cleanup;
    }
    buf_ptr += n2;
    n += n2;
    if (base64_encode_update (&x, buf_ptr, &n2, c->mac, c->mac_len) < 0) {
        goto err_cleanup;
    }
    buf_ptr += n2;
    n += n2;
    if (base64_encode_update (&x, buf_ptr, &n2, c->inner, c->inner_len) < 0) {
        goto err_cleanup;
    }
    buf_ptr += n2;
    n += n2;
    if (base64_encode_final (&x, buf_ptr, &n2) < 0) {
        goto err_cleanup;
    }
    buf_ptr += n2;
    n += n2;
    if (base64_cleanup (&x) < 0) {
        goto err;
    }
    n++;                                /* count the terminating NUL char */

    /*  Add the suffix string.
     */
    if (suffix_len > 0) {
        strcpy ((char *) buf_ptr, MUNGE_CRED_SUFFIX); /* strcpy() safe here */
        buf_ptr += suffix_len;
    }
    assert ((buf_ptr - buf) < buf_len);

    /*  Replace "outer+inner" data with armor'd data.
     */
    assert (c->outer_mem_len > 0);
    memset (c->outer_mem, 0, c->outer_mem_len);
    free (c->outer_mem);

    c->outer_mem = buf;
    c->outer_mem_len = buf_len;
    c->outer = buf;
    c->outer_len = buf_ptr - buf + 1;

    assert (c->inner_mem_len > 0);
    memset (c->inner_mem, 0, c->inner_mem_len);
    free (c->inner_mem);

    c->inner_mem = NULL;
    c->inner_mem_len = 0;
    return (0);

err_cleanup:
    base64_cleanup (&x);
err:
    memset (buf, 0, buf_len);
    free (buf);
    return (m_msg_set_err (m, EMUNGE_SNAFU,
        strdup ("Failed to base64-encode credential")));
}


static int
enc_fini (munge_cred_t c)
{
/*  Finalizes encoding a credential, ensuring it is ready for transit.
 */
    m_msg_t  m = c->msg;

    /*  Free any "request data".
     */
    if (m->data) {
        assert (m->data_len > 0);
        assert (m->data_is_copy == 0);
        free (m->data);
    }
    /*  Place credential in message "data" payload for transit.
     *  This memory is still owned by the cred struct, so it will be
     *    free()d by cred_destroy() called from enc_process_msg().
     */
    m->data = c->outer;
    m->data_len = c->outer_len;
    m->data_is_copy = 1;
    return (0);
}
