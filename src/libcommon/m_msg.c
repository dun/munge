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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <munge.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>                   /* gettimeofday */
#include <sys/uio.h>
#include <unistd.h>
#include "fd.h"
#include "m_msg.h"
#include "munge_defs.h"
#include "str.h"


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef void ** vpp;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void _get_timeval (struct timeval *tv, int msecs);
static int _msg_length (m_msg_t m, m_msg_type_t type);
static munge_err_t _msg_pack (m_msg_t m, m_msg_type_t type,
        void *dst, int dstlen);
static munge_err_t _msg_unpack (m_msg_t m, m_msg_type_t type,
        const void *src, int srclen);
static int _alloc (void **pdst, int len);
static int _copy (void *dst, void *src, int len,
        const void *first, const void *last, void **pinc);
static int _pack (void **pdst, void *src, int len, const void *last);
static int _unpack (void *dst, void **psrc, int len, const void *last);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
m_msg_create (m_msg_t *pm)
{
/*  Creates a message (passed by reference) for sending over the munge socket.
 *  Returns a standard munge error code.
 */
    m_msg_t m;

    assert (pm != NULL);

    if (!(m = calloc (1, sizeof (*m)))) {
        *pm = NULL;
        return (EMUNGE_NO_MEMORY);
    }
    m->sd = -1;
    m->type = MUNGE_MSG_UNDEF;

    *pm = m;
    return (EMUNGE_SUCCESS);
}


void
m_msg_destroy (m_msg_t m)
{
/*  Destroys the message [m].
 */
    assert (m != NULL);

    if (m->sd >= 0) {
        (void) close (m->sd);
    }
    if (m->pkt && !m->pkt_is_copy) {
        assert (m->pkt_len > 0);
        free (m->pkt);
    }
    if (m->realm_str && !m->realm_is_copy) {
        assert (m->realm_len > 0);
        free (m->realm_str);
    }
    if (m->data && !m->data_is_copy) {
        assert (m->data_len > 0);
        free (m->data);
    }
    if (m->error_str && !m->error_is_copy) {
        assert (m->error_len > 0);
        free (m->error_str);
    }
    if (m->auth_s_str && !m->auth_s_is_copy) {
        assert (m->auth_s_len > 0);
        free (m->auth_s_str);
    }
    if (m->auth_c_str && !m->auth_c_is_copy) {
        assert (m->auth_c_len > 0);
        free (m->auth_c_str);
    }
    free (m);
    return;
}


void
m_msg_reset (m_msg_t m)
{
/*  Reset sensitive fields in the message [m] that could leak information.
 */
    assert (m != NULL);

    m->cipher = MUNGE_CIPHER_NONE;
    m->mac = MUNGE_MAC_NONE;
    m->zip = MUNGE_ZIP_NONE;
    m->realm_len = 0;
    if (m->realm_str) {
        if (!m->realm_is_copy) {
            free (m->realm_str);
        }
        m->realm_str = NULL;
    }
    m->ttl = MUNGE_TTL_DEFAULT;
    m->addr_len = 0;
    m->time0 = 0;
    m->time1 = 0;
    m->cred_uid = MUNGE_UID_ANY;
    m->cred_gid = MUNGE_GID_ANY;
    m->auth_uid = MUNGE_UID_ANY;
    m->auth_gid = MUNGE_GID_ANY;
    m->data_len = 0;
    if (m->data) {
        if (!m->data_is_copy) {
            free (m->data);
        }
        m->data = NULL;
    }
    return;
}


munge_err_t
m_msg_bind (m_msg_t m, int sd)
{
/*  Binds the message [m] to the socket [sd].
 */
    assert (m != NULL);

    if (m->sd >= 0) {
        (void) close (m->sd);
    }
    m->sd = sd;
    return (EMUNGE_SUCCESS);
}


munge_err_t
m_msg_send (m_msg_t m, m_msg_type_t type, int maxlen)
{
/*  Sends the message [m] of type [type] to the recipient at the other end
 *    of the already-specified socket.
 *  If [maxlen] > 0, message bodies larger than this value will be discarded
 *    and an error returned.
 *  Returns a standard munge error code.
 */
    munge_err_t     e;
    int             n, nsend;
    uint8_t         hdr [MUNGE_MSG_HDR_SIZE];
    struct iovec    iov [2];
    struct timeval  tv;

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (type != MUNGE_MSG_UNDEF);
    assert (type != MUNGE_MSG_HDR);

    /*  If the stored message type [m->type] does not match the given
     *    message type [type], clean up the old packed message body.
     */
    if (m->type != type) {
        if (m->pkt) {
            assert (m->pkt_len > 0);
            if (!m->pkt_is_copy) {
                free (m->pkt);
            }
            m->pkt = NULL;
            m->pkt_len = 0;
            m->pkt_is_copy = 0;
        }
    }
    /*  If a previously packed message body does not already exist,
     *    create & pack the message body.
     */
    if (!m->pkt) {
        assert (m->pkt_len == 0);
        assert (m->pkt_is_copy == 0);
        if ((n = _msg_length (m, type)) <= 0) {
            m_msg_set_err (m, EMUNGE_NO_MEMORY,
                strdupf ("Failed to compute length for message type %d n=%d",
                    type, n));
            return (EMUNGE_SNAFU);
        }
        if (!(m->pkt = malloc (n))) {
            m_msg_set_err (m, EMUNGE_NO_MEMORY,
                strdupf ("Failed to allocate %d bytes for sending message",
                    n));
            return (EMUNGE_NO_MEMORY);
        }
        m->pkt_len = n;
        m->type = type;
        e = _msg_pack (m, type, m->pkt, m->pkt_len);
        if (e != EMUNGE_SUCCESS) {
            m_msg_set_err (m, e,
                strdup ("Failed to pack message body"));
            return (e);
        }
    }
    /*  Check if the message exceeds the maximum allowed length.
     */
    if ((maxlen > 0) && (m->pkt_len > maxlen)) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to send message: "
                "length of %d exceeds max of %d", m->pkt_len, maxlen));
        return (EMUNGE_BAD_LENGTH);
    }
    /*  Always repack the message header.
     */
    e = _msg_pack (m, MUNGE_MSG_HDR, hdr, sizeof (hdr));
    if (e != EMUNGE_SUCCESS) {
        m_msg_set_err (m, e,
            strdup ("Failed to pack message header"));
        return (e);
    }
    /*  Compute iovec for response header + body.
     */
    nsend = 0;
    iov[0].iov_base = (void *) hdr;
    nsend += iov[0].iov_len = sizeof (hdr);
    iov[1].iov_base = m->pkt;
    nsend += iov[1].iov_len = m->pkt_len;

    /*  Compute maximum time to wait for transmission of message.
     */
    _get_timeval (&tv, MUNGE_SOCKET_TIMEOUT_MSECS);

    /*  Send the message.
     */
    if ((errno = 0, n = fd_timed_write_iov (m->sd, iov, 2, &tv, 1)) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to send message: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    else if (errno == ETIMEDOUT) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to send message: Timed-out"));
        return (EMUNGE_SOCKET);
    }
    else if (n != nsend) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Sent incomplete message: %d of %d bytes", n, nsend));
        return (EMUNGE_SOCKET);
    }
    return (EMUNGE_SUCCESS);

}


munge_err_t
m_msg_recv (m_msg_t m, m_msg_type_t type, int maxlen)
{
/*  Receives a message from the sender at the other end of the
 *    already-specified socket.  This message is stored in the
 *    previously-created [m].
 *  If a [type] is specified (ie, not MUNGE_MSG_UNDEF) and does not match
 *    the header type, the message will be discarded and an error returned.
 *  If [maxlen] > 0, message bodies larger than this value will be discarded
 *    and an error returned.
 *  Returns a standard munge error code.
 */
    int             n, nrecv;
    uint8_t         hdr [MUNGE_MSG_HDR_SIZE];
    struct timeval  tv;

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (m->type != MUNGE_MSG_HDR);
    assert (m->pkt == NULL);
    assert (m->pkt_len == 0);
    assert (m->pkt_is_copy == 0);
    assert (_msg_length (m, MUNGE_MSG_HDR) == MUNGE_MSG_HDR_SIZE);

    /*  Compute maximum time to wait for receipt of message.
     */
    _get_timeval (&tv, MUNGE_SOCKET_TIMEOUT_MSECS);

    /*  Read and validate the message header.
     */
    nrecv = sizeof (hdr);
    if ((errno = 0, n = fd_timed_read_n (m->sd, &hdr, nrecv, &tv, 1)) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to receive message header: %s",
                strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    else if (errno == ETIMEDOUT) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to receive message header: Timed-out"));
        return (EMUNGE_SOCKET);
    }
    else if (n != nrecv) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message header: %d of %d bytes",
            n, nrecv));
        return (EMUNGE_SOCKET);
    }
    else if (_msg_unpack (m, MUNGE_MSG_HDR, hdr, sizeof (hdr))
            != EMUNGE_SUCCESS) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to unpack message header"));
        return (EMUNGE_SOCKET);
    }
    else if ((type != MUNGE_MSG_UNDEF) && (m->type != type)) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received unexpected message type: wanted %d, got %d",
                type, m->type));
        return (EMUNGE_SOCKET);
    }
    else if ((maxlen > 0) && (m->pkt_len > maxlen)) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to receive message: "
                "length of %d exceeds max of %d", m->pkt_len, maxlen));
        return (EMUNGE_BAD_LENGTH);
    }
    else if (!(m->pkt = malloc (m->pkt_len))) {
        m_msg_set_err (m, EMUNGE_NO_MEMORY,
            strdupf ("Failed to allocate %d bytes for receiving message", n));
        return (EMUNGE_NO_MEMORY);
    }
    else if ((errno = 0,
              n = fd_timed_read_n (m->sd, m->pkt, m->pkt_len, &tv, 1)) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to receive message body: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    else if (errno == ETIMEDOUT) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to receive message body: Timed-out"));
        return (EMUNGE_SOCKET);
    }
    else if (n != m->pkt_len) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message body: %d of %d bytes",
            n, nrecv));
        return (EMUNGE_SOCKET);
    }
    else if (_msg_unpack (m, m->type, m->pkt, m->pkt_len) != EMUNGE_SUCCESS) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to unpack message body"));
        return (EMUNGE_SOCKET);
    }
    /*  The packed message can be discarded now that it's been unpacked.
     */
    free (m->pkt);
    m->pkt = NULL;
    m->pkt_len = 0;
    assert (m->pkt_is_copy == 0);
    return (EMUNGE_SUCCESS);
}


int
m_msg_set_err (m_msg_t m, munge_err_t e, char *s)
{
/*  Set an error code [e] and string [s] if an error condition
 *    does not already exist (ie, m->error_num == EMUNGE_SUCCESS).
 *    Thus, if multiple errors are set, only the first one is reported.
 *  If [s] is not NULL, that string (and _not_ a copy) will be stored
 *    and later free()'d by the message destructor; if [s] is NULL,
 *    munge_strerror() will be used to obtain a descriptive string.
 *  Always returns -1 and consumes [s].
 */
    assert (m != NULL);

    if ((m->error_num == EMUNGE_SUCCESS) && (e != EMUNGE_SUCCESS)) {
        m->error_num = e;
        assert (m->error_str == NULL);
        assert (m->error_len == 0);
        assert (m->error_is_copy == 0);
        m->error_str = (s != NULL) ? s : strdup (munge_strerror (e));
        m->error_len = strlen (m->error_str) + 1;
    }
    else if (s) {
        free (s);
    }
    /*  "Screw you guys, I'm goin' home." -ecartman
     */
    return (-1);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void
_get_timeval (struct timeval *tv, int msecs)
{
/*  Sets [tv] to the current time adjusted forward by [msecs] milliseconds.
 */
    assert (tv != NULL);

    if (gettimeofday (tv, NULL) < 0) {
        tv->tv_sec = tv->tv_usec = 0;
    }
    if (msecs > 0) {
        tv->tv_sec += msecs / 1000;
        tv->tv_usec += (msecs % 1000) * 1000;
        if (tv->tv_usec >= 1000000) {
            tv->tv_sec += tv->tv_usec / 1000000;
            tv->tv_usec %= 1000000;
        }
    }
    return;
}


static int
_msg_length (m_msg_t m, m_msg_type_t type)
{
/*  Returns the length needed to pack the message [m] of type [type].
 */
    int n = 0;

    assert (m != NULL);

    switch (type) {
        case MUNGE_MSG_HDR:
            n += sizeof (m_msg_magic_t);
            n += sizeof (m_msg_version_t);
            n += sizeof (m->type);
            n += sizeof (m->retry);
            n += sizeof (m->pkt_len);
            break;
        case MUNGE_MSG_ENC_REQ:
            n += sizeof (m->cipher);
            n += sizeof (m->mac);
            n += sizeof (m->zip);
            n += sizeof (m->realm_len);
            n += m->realm_len;
            n += sizeof (m->ttl);
            n += sizeof (m->auth_uid);
            n += sizeof (m->auth_gid);
            n += sizeof (m->data_len);
            n += m->data_len;
            break;
        case MUNGE_MSG_ENC_RSP:
            n += sizeof (m->error_num);
            n += sizeof (m->error_len);
            n += m->error_len;
            n += sizeof (m->data_len);
            n += m->data_len;
            break;
        case MUNGE_MSG_DEC_REQ:
            n += sizeof (m->data_len);
            n += m->data_len;
            break;
        case MUNGE_MSG_DEC_RSP:
            n += sizeof (m->error_num);
            n += sizeof (m->error_len);
            n += m->error_len;
            n += sizeof (m->cipher);
            n += sizeof (m->mac);
            n += sizeof (m->zip);
            n += sizeof (m->realm_len);
            n += m->realm_len;
            n += sizeof (m->ttl);
            n += sizeof (m->addr_len);
            n += m->addr_len;
            n += sizeof (m->time0);
            n += sizeof (m->time1);
            n += sizeof (m->cred_uid);
            n += sizeof (m->cred_gid);
            n += sizeof (m->auth_uid);
            n += sizeof (m->auth_gid);
            n += sizeof (m->data_len);
            n += m->data_len;
            break;
        case MUNGE_MSG_AUTH_FD_REQ:
            n += sizeof (m->auth_s_len);
            n += m->auth_s_len;
            n += sizeof (m->auth_c_len);
            n += m->auth_c_len;
            break;
        default:
            return (-1);
            break;
    }
    return (n);
}


static munge_err_t
_msg_pack (m_msg_t m, m_msg_type_t type, void *dst, int dstlen)
{
/*  Packs the message [m] of type [type] into the buffer [dst]
 *    of length [dstlen] for transport across the munge socket.
 */
    m_msg_magic_t    magic = MUNGE_MSG_MAGIC;
    m_msg_version_t  version = MUNGE_MSG_VERSION;
    void            *p = dst;
    void            *q = (unsigned char *) dst + dstlen;

    assert (m != NULL);

    switch (type) {
        case MUNGE_MSG_HDR:
            if      (!_pack (&p, &magic, sizeof (magic), q)) ;
            else if (!_pack (&p, &version, sizeof (version), q)) ;
            else if (!_pack (&p, &(m->type), sizeof (m->type), q)) ;
            else if (!_pack (&p, &(m->retry), sizeof (m->retry), q)) ;
            else if (!_pack (&p, &(m->pkt_len), sizeof (m->pkt_len), q)) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_REQ:
            if      (!_pack (&p, &(m->cipher), sizeof (m->cipher), q)) ;
            else if (!_pack (&p, &(m->mac), sizeof (m->mac), q)) ;
            else if (!_pack (&p, &(m->zip), sizeof (m->zip), q)) ;
            else if (!_pack (&p, &(m->realm_len), sizeof (m->realm_len), q)) ;
            else if ( _copy (p, m->realm_str, m->realm_len, p, q, &p) < 0) ;
            else if (!_pack (&p, &(m->ttl), sizeof (m->ttl), q)) ;
            else if (!_pack (&p, &(m->auth_uid), sizeof (m->auth_uid), q)) ;
            else if (!_pack (&p, &(m->auth_gid), sizeof (m->auth_gid), q)) ;
            else if (!_pack (&p, &(m->data_len), sizeof (m->data_len), q)) ;
            else if ( _copy (p, m->data, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_RSP:
            if      (!_pack (&p, &(m->error_num), sizeof (m->error_num), q)) ;
            else if (!_pack (&p, &(m->error_len), sizeof (m->error_len), q)) ;
            else if ( _copy (p, m->error_str, m->error_len, p, q, &p) < 0) ;
            else if (!_pack (&p, &(m->data_len), sizeof (m->data_len), q)) ;
            else if ( _copy (p, m->data, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_REQ:
            if      (!_pack (&p, &(m->data_len), sizeof (m->data_len), q)) ;
            else if ( _copy (p, m->data, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_RSP:
            if      (!_pack (&p, &(m->error_num), sizeof (m->error_num), q)) ;
            else if (!_pack (&p, &(m->error_len), sizeof (m->error_len), q)) ;
            else if ( _copy (p, m->error_str, m->error_len, p, q, &p) < 0) ;
            else if (!_pack (&p, &(m->cipher), sizeof (m->cipher), q)) ;
            else if (!_pack (&p, &(m->mac), sizeof (m->mac), q)) ;
            else if (!_pack (&p, &(m->zip), sizeof (m->zip), q)) ;
            else if (!_pack (&p, &(m->realm_len), sizeof (m->realm_len), q)) ;
            else if ( _copy (p, m->realm_str, m->realm_len, p, q, &p) < 0) ;
            else if (!_pack (&p, &(m->ttl), sizeof (m->ttl), q)) ;
            else if (!_pack (&p, &(m->addr_len), sizeof (m->addr_len), q)) ;
            else if ( _copy (p, &(m->addr), m->addr_len, p, q, &p) < 0) ;
            else if (!_pack (&p, &(m->time0), sizeof (m->time0), q)) ;
            else if (!_pack (&p, &(m->time1), sizeof (m->time1), q)) ;
            else if (!_pack (&p, &(m->cred_uid), sizeof (m->cred_uid), q)) ;
            else if (!_pack (&p, &(m->cred_gid), sizeof (m->cred_gid), q)) ;
            else if (!_pack (&p, &(m->auth_uid), sizeof (m->auth_uid), q)) ;
            else if (!_pack (&p, &(m->auth_gid), sizeof (m->auth_gid), q)) ;
            else if (!_pack (&p, &(m->data_len), sizeof (m->data_len), q)) ;
            else if ( _copy (p, m->data, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_AUTH_FD_REQ:
            if      (!_pack (&p, &(m->auth_s_len), sizeof (m->auth_s_len), q));
            else if ( _copy (p, m->auth_s_str, m->auth_s_len, p, q, &p) < 0) ;
            else if (!_pack (&p, &(m->auth_c_len), sizeof (m->auth_c_len), q));
            else if ( _copy (p, m->auth_c_str, m->auth_c_len, p, q, &p) < 0) ;
            else break;
            goto err;
        default:
            goto err;
    }
    return (EMUNGE_SUCCESS);

err:
    m_msg_set_err (m, EMUNGE_SNAFU,
        strdupf ("Failed to pack message type %d", type));
    return (EMUNGE_SNAFU);
}


static munge_err_t
_msg_unpack (m_msg_t m, m_msg_type_t type, const void *src, int srclen)
{
/*  Unpacks the message [m] from transport across the munge socket.
 *  Checks to ensure the message is of the expected type [type].
 */
    m_msg_magic_t    magic;
    m_msg_version_t  version;
    void            *p = (void *) src;
    void            *q = (unsigned char *) src + srclen;

    assert (m != NULL);

    switch (type) {
        case MUNGE_MSG_HDR:
            if      (!_unpack (&magic, &p, sizeof (magic), q)) ;
            else if (!_unpack (&version, &p, sizeof (version), q)) ;
            else if (!_unpack (&(m->type), &p, sizeof (m->type), q)) ;
            else if (!_unpack (&(m->retry), &p, sizeof (m->retry), q)) ;
            else if (!_unpack (&(m->pkt_len), &p, sizeof (m->pkt_len), q)) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_REQ:
            if      (!_unpack (&(m->cipher), &p, sizeof (m->cipher), q)) ;
            else if (!_unpack (&(m->mac), &p, sizeof (m->mac), q)) ;
            else if (!_unpack (&(m->zip), &p, sizeof (m->zip), q)) ;
            else if (!_unpack (&(m->realm_len), &p, sizeof (m->realm_len), q));
            else if (!_alloc ((vpp) &(m->realm_str), m->realm_len)) goto nomem;
            else if ( _copy (m->realm_str, p, m->realm_len, p, q, &p) < 0) ;
            else if (!_unpack (&(m->ttl), &p, sizeof (m->ttl), q)) ;
            else if (!_unpack (&(m->auth_uid), &p, sizeof (m->auth_uid), q)) ;
            else if (!_unpack (&(m->auth_gid), &p, sizeof (m->auth_gid), q)) ;
            else if (!_unpack (&(m->data_len), &p, sizeof (m->data_len), q)) ;
            else if (!_alloc (&(m->data), m->data_len)) goto nomem;
            else if ( _copy (m->data, p, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_RSP:
            if      (!_unpack (&(m->error_num), &p, sizeof (m->error_num), q));
            else if (!_unpack (&(m->error_len), &p, sizeof (m->error_len), q));
            else if (!_alloc ((vpp) &(m->error_str), m->error_len)) goto nomem;
            else if ( _copy (m->error_str, p, m->error_len, p, q, &p) < 0) ;
            else if (!_unpack (&(m->data_len), &p, sizeof (m->data_len), q)) ;
            else if (!_alloc (&(m->data), m->data_len)) goto nomem;
            else if ( _copy (m->data, p, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_REQ:
            if      (!_unpack (&(m->data_len), &p, sizeof (m->data_len), q)) ;
            else if (!_alloc (&(m->data), m->data_len)) goto nomem;
            else if ( _copy (m->data, p, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_RSP:
            if      (!_unpack (&(m->error_num), &p, sizeof (m->error_num), q));
            else if (!_unpack (&(m->error_len), &p, sizeof (m->error_len), q));
            else if (!_alloc ((vpp) &(m->error_str), m->error_len)) goto nomem;
            else if ( _copy (m->error_str, p, m->error_len, p, q, &p) < 0) ;
            else if (!_unpack (&(m->cipher), &p, sizeof (m->cipher), q)) ;
            else if (!_unpack (&(m->mac), &p, sizeof (m->mac), q)) ;
            else if (!_unpack (&(m->zip), &p, sizeof (m->zip), q)) ;
            else if (!_unpack (&(m->realm_len), &p, sizeof (m->realm_len), q));
            else if (!_alloc ((vpp) &(m->realm_str), m->realm_len)) goto nomem;
            else if ( _copy (m->realm_str, p, m->realm_len, p, q, &p) < 0) ;
            else if (!_unpack (&(m->ttl), &p, sizeof (m->ttl), q)) ;
            else if (!_unpack (&(m->addr_len), &p, sizeof (m->addr_len), q)) ;
            else if ( _copy (&(m->addr), p, m->addr_len, p, q, &p) < 0) ;
            else if (!_unpack (&(m->time0), &p, sizeof (m->time0), q)) ;
            else if (!_unpack (&(m->time1), &p, sizeof (m->time1), q)) ;
            else if (!_unpack (&(m->cred_uid), &p, sizeof (m->cred_uid), q)) ;
            else if (!_unpack (&(m->cred_gid), &p, sizeof (m->cred_gid), q)) ;
            else if (!_unpack (&(m->auth_uid), &p, sizeof (m->auth_uid), q)) ;
            else if (!_unpack (&(m->auth_gid), &p, sizeof (m->auth_gid), q)) ;
            else if (!_unpack (&(m->data_len), &p, sizeof (m->data_len), q)) ;
            else if (!_alloc (&(m->data), m->data_len)) goto nomem;
            else if ( _copy (m->data, p, m->data_len, p, q, &p) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_AUTH_FD_REQ:
            if      (!_unpack(&(m->auth_s_len), &p, sizeof(m->auth_s_len), q));
            else if (!_alloc((vpp)&(m->auth_s_str), m->auth_s_len)) goto nomem;
            else if ( _copy (m->auth_s_str, p, m->auth_s_len, p, q, &p) < 0) ;
            else if (!_unpack(&(m->auth_c_len), &p, sizeof(m->auth_c_len), q));
            else if (!_alloc((vpp)&(m->auth_c_str), m->auth_c_len)) goto nomem;
            else if ( _copy (m->auth_c_str, p, m->auth_c_len, p, q, &p) < 0) ;
            else break;
            goto err;
        default:
            goto err;
    }
    assert (p == (unsigned char *) src + srclen);

    if (type == MUNGE_MSG_HDR) {
        if (magic != MUNGE_MSG_MAGIC) {
            m_msg_set_err (m, EMUNGE_SOCKET,
                strdupf ("Received invalid message magic %d", magic));
            return (EMUNGE_SOCKET);
        }
        else if (version != MUNGE_MSG_VERSION) {
            m_msg_set_err (m, EMUNGE_SOCKET,
                strdupf ("Received invalid message version %d", version));
            return (EMUNGE_SOCKET);
        }
    }
    return (EMUNGE_SUCCESS);

err:
    m_msg_set_err (m, EMUNGE_SNAFU,
        strdupf ("Failed to unpack message type %d", type));
    return (EMUNGE_SNAFU);

nomem:
    m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL);
    return (EMUNGE_NO_MEMORY);
}


static int
_alloc (void **pdst, int len)
{
/*  Allocates memory for [pdst] of length [len + 1],
 *    NUL-terminating the last byte.
 *  Returns non-zero on success; o/w, returns 0.
 */
    unsigned char *p;

    assert (pdst != NULL);
    assert (*pdst == NULL);

    if (len == 0) {                     /* valid no-op */
        return (1);
    }
    if (len < 0) {                      /* invalid length */
        return (0);
    }
    /*  Allocate an extra byte to NUL-terminate the memory allocation.
     */
    if (!(p = malloc (len + 1))) {
        return (0);
    }
    p[len] = '\0';
    *pdst = p;
    return (1);
}


static int
_copy (void *dst, void *src, int len,
       const void *first, const void *last, void **pinc)
{
/*  Copies [len] bytes of data from [src] to [dst].
 *    If [first] and [last] are both non-NULL, checks to ensure
 *    [len] bytes of data resides between [first] and [last].
 *  Returns the number of bytes copied into [dst], or -1 on error.
 *    On success (ie, >= 0), an optional [inc] ptr is advanced by [len].
 */
    if (len < 0) {
        return (-1);
    }
    if (len == 0) {
        return (0);
    }
    if ((first != NULL) && (last != NULL)
            && ((unsigned char *) first + len > (unsigned char *) last)) {
        return (-1);
    }
    if (len > 0) {
        memcpy (dst, src, len);
    }
    if (pinc != NULL) {
        *pinc = (unsigned char *) *pinc + len;
    }
    return (len);
}


static int
_pack (void **pdst, void *src, int len, const void *last)
{
/*  Packs the [src] data of [len] bytes into [dst] using MSBF.
 *    If [last] is non-NULL, checks to ensure [len] bytes
 *    of [dst] data resides prior to the [last] valid byte.
 *  Returns the number of bytes copied into [dst].
 *    On success (ie, > 0), the [dst] ptr is advanced by [len].
 */
    void     *dst;
    uint16_t  u16;
    uint32_t  u32;

    assert (pdst != NULL);
    assert (src != NULL);

    dst = *pdst;
    if (last && ((unsigned char *) dst + len > (unsigned char *) last)) {
        return (0);
    }
    switch (len) {
        case (sizeof (uint8_t)):
            * (uint8_t *) dst = * (uint8_t *) src;
            break;
        case (sizeof (uint16_t)):
            u16 = htons (* (uint16_t *) src);
            memcpy (dst, &u16, len);
            break;
        case (sizeof (uint32_t)):
            u32 = htonl (* (uint32_t *) src);
            memcpy (dst, &u32, len);
            break;
        default:
            return (0);
    }
    *pdst = (unsigned char *) dst + len;
    return (len);
}


static int
_unpack (void *dst, void **psrc, int len, const void *last)
{
/*  Unpacks the MSBF [src] data of [len] bytes into [dst].
 *    If [last] is non-NULL, checks to ensure [len] bytes
 *    of [src] data resides prior to the [last] valid byte.
 *  Returns the number of bytes copied into [dst].
 *    On success (ie, > 0), the [src] ptr is advanced by [len].
 */
    void     *src;
    uint16_t  u16;
    uint32_t  u32;

    assert (dst != NULL);
    assert (psrc != NULL);

    src = *psrc;
    if (last && ((unsigned char *) src + len > (unsigned char *) last)) {
        return (0);
    }
    switch (len) {
        case (sizeof (uint8_t)):
            * (uint8_t *) dst = * (uint8_t *) src;
            break;
        case (sizeof (uint16_t)):
            memcpy (&u16, src, len);
            * (uint16_t *) dst = ntohs (u16);
            break;
        case (sizeof (uint32_t)):
            memcpy (&u32, src, len);
            * (uint32_t *) dst = ntohl (u32);
            break;
        default:
            return (0);
    }
    *psrc = (unsigned char *) src + len;
    return (len);
}
