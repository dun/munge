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
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "m_msg.h"

#include "fd.h"
#include "memwipe.h"
#include "munge_defs.h"
#include "str.h"

#include <munge.h>

#include <arpa/inet.h>                  /* htonl, htons, ntohl, ntohs */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>                   /* PRIu32 */
#include <limits.h>                     /* INT_MAX */
#include <stddef.h>                     /* size_t */
#include <stdint.h>                     /* uint8_t, uint16_t, uint32_t, UINT8_MAX */
#include <stdlib.h>                     /* calloc, malloc, free */
#include <string.h>                     /* memccpy, memcpy, strdup, strlen */
#include <sys/time.h>                   /* gettimeofday, timeval */
#include <sys/uio.h>                    /* iovec */
#include <unistd.h>                     /* close */


/******************************************************************************
 *  Data Types
 *****************************************************************************/

typedef void ** vpp;


/******************************************************************************
 *  Prototypes
 *****************************************************************************/

static void _get_timeval (struct timeval *tv, int msecs);
static int _msg_length (m_msg_t m, m_msg_type_t type);
static munge_err_t _msg_pack (m_msg_t m, m_msg_type_t type,
        void *dst, int dstlen);
static munge_err_t _msg_unpack (m_msg_t m, m_msg_type_t type,
        const void *src, int srclen);
static int _alloc (void **pdst, int len);
static int _copy (void *dst, const void *src, int len,
        void **pfirst, const void *last);
static int _pack (void **pdst, const void *src, int len, const void *last);
static int _unpack (void *dst, void **psrc, int len, const void *last);


/******************************************************************************
 *  Public Functions
 *****************************************************************************/

/**
 *  Create a message and return it by reference via [pm] for transfer over the
 *  munge socket.
 *
 *  Return a standard munge error code.
 */
munge_err_t
m_msg_create (m_msg_t *pm)
{
    m_msg_t m;

    assert (pm != NULL);

    if (!(m = calloc (1, sizeof *m))) {
        *pm = NULL;
        return EMUNGE_NO_MEMORY;
    }
    m->sd = -1;
    m->type = MUNGE_MSG_UNDEF;

    *pm = m;
    return EMUNGE_SUCCESS;
}


/**
 *  Destroy the message [m], closing its bound socket and freeing every buffer
 *  it owns (those not marked as a copy).
 */
void
m_msg_destroy (m_msg_t m)
{
    assert (m != NULL);

    if (m->sd >= 0) {
        (void) close (m->sd);
    }
    if (m->pkt && !m->pkt_is_copy) {
        assert (m->pkt_len > 0);
        memwipe_and_free (m->pkt, (size_t) m->pkt_len);
    }
    if (m->realm_str && !m->realm_is_copy) {
        assert (m->realm_len > 0);
        free (m->realm_str);
    }
    if (m->data && !m->data_is_copy) {
        assert (m->data_len > 0);
        memwipe_and_free (m->data, (size_t) m->data_len);
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
}


/**
 *  Reset the request-derived fields of message [m] so it can be reused to
 *  carry the response for the same transaction.
 *
 *  Clear the option and payload fields that a request populates, and wipe
 *  [data] since it may hold a sensitive payload.  This keeps a request's
 *  contents from leaking into an error response.
 *
 *  Deliberately preserve [error_num] and [error_str]: they are set while
 *  processing the request and must survive into the response, which is how an
 *  error is returned to the client (see m_msg_set_err()).  [type], [retry],
 *  [pkt], and the client identity are likewise left untouched.
 */
void
m_msg_reset (m_msg_t m)
{
    assert (m != NULL);

    m->cipher = MUNGE_CIPHER_NONE;
    m->mac = MUNGE_MAC_NONE;
    m->zip = MUNGE_ZIP_NONE;
    if (m->realm_str) {
        if (!m->realm_is_copy) {
            free (m->realm_str);
        }
        m->realm_str = NULL;
        m->realm_len = 0;
        m->realm_is_copy = 0;
    }
    m->ttl = MUNGE_TTL_DEFAULT;
    m->addr_len = 0;
    m->time0 = 0;
    m->time1 = 0;
    m->cred_uid = MUNGE_UID_ANY;
    m->cred_gid = MUNGE_GID_ANY;
    m->auth_uid = MUNGE_UID_ANY;
    m->auth_gid = MUNGE_GID_ANY;
    if (m->data) {
        assert (m->data_len > 0);       /* in sync; used as memwipe size */
        if (!m->data_is_copy) {
            memwipe_and_free (m->data, (size_t) m->data_len);
        }
        m->data = NULL;
        m->data_len = 0;
        m->data_is_copy = 0;
    }
}


/**
 *  Bind the message [m] to the socket [sd], closing any socket already bound
 *  to [m] first.
 *
 *  Return a standard munge error code.
 */
munge_err_t
m_msg_bind (m_msg_t m, int sd)
{
    assert (m != NULL);

    if (sd < 0) {
        return EMUNGE_BAD_ARG;
    }
    if (m->sd >= 0) {
        (void) close (m->sd);           /* prevent leaking live sd */
    }
    m->sd = sd;
    return EMUNGE_SUCCESS;
}


/**
 *  Send the message [m] of type [type] over its bound socket.
 *
 *  Pack and cache the message body on the first send of a given [type],
 *  reusing the cached body on a subsequent send (retry); a change of [type]
 *  discards the cached body and repacks.
 *
 *  If [maxlen] > 0, reject a message body larger than [maxlen] bytes with
 *  EMUNGE_BAD_LENGTH.
 *
 *  Return a standard munge error code.
 */
munge_err_t
m_msg_send (m_msg_t m, m_msg_type_t type, size_t maxlen)
{
    munge_err_t e;
    int n, nsend;
    uint8_t hdr[MUNGE_MSG_HDR_SIZE];
    struct iovec iov[2];
    struct timeval tv;

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (type != MUNGE_MSG_UNDEF);
    assert (type != MUNGE_MSG_HDR);

    /*  If the stored message type [m->type] does not match the given
     *  message type [type], clean up the old packed message body.
     */
    if (m->type != type) {
        if (m->pkt) {
            assert (m->pkt_len > 0);
            if (!m->pkt_is_copy) {
                memwipe_and_free (m->pkt, (size_t) m->pkt_len);
            }
            m->pkt = NULL;
            m->pkt_len = 0;
            m->pkt_is_copy = 0;
        }
    }
    /*  If a previously packed message body does not already exist,
     *  create & pack the message body.
     */
    if (!m->pkt) {
        assert (m->pkt_len == 0);
        assert (m->pkt_is_copy == 0);
        if ((n = _msg_length (m, type)) <= 0) {
            m_msg_set_err (m, EMUNGE_SNAFU,
                strdupf ("Failed to compute length for message type %d n=%d",
                    type, n));
            return EMUNGE_SNAFU;
        }
        if (!(m->pkt = malloc (n))) {
            m_msg_set_err (m, EMUNGE_NO_MEMORY,
                strdupf ("Failed to allocate %d bytes for sending message",
                    n));
            return EMUNGE_NO_MEMORY;
        }
        m->pkt_len = n;
        m->type = type;
        e = _msg_pack (m, type, m->pkt, m->pkt_len);
        if (e != EMUNGE_SUCCESS) {
            m_msg_set_err (m, e,
                strdup ("Failed to pack message body"));
            return e;
        }
    }
    /*  Check if the message exceeds the maximum allowed length.
     */
    if ((maxlen > 0) && (m->pkt_len > maxlen)) {
        m_msg_set_err (m, EMUNGE_BAD_LENGTH,
            strdupf ("Failed to send message: Size %" PRIu32
                " exceeded maximum of %zu", m->pkt_len, maxlen));
        return EMUNGE_BAD_LENGTH;
    }
    /*  Always repack the message header.
     */
    e = _msg_pack (m, MUNGE_MSG_HDR, hdr, sizeof hdr);
    if (e != EMUNGE_SUCCESS) {
        m_msg_set_err (m, e,
            strdup ("Failed to pack message header"));
        return e;
    }
    /*  Compute iovec for response header + body.
     */
    nsend = 0;
    iov[0].iov_base = hdr;
    nsend += iov[0].iov_len = sizeof hdr;
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
        return EMUNGE_SOCKET;
    }
    else if (errno == ETIMEDOUT) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to send message: Timed-out"));
        return EMUNGE_SOCKET;
    }
    else if (n != nsend) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Sent incomplete message: %d of %d bytes", n, nsend));
        return EMUNGE_SOCKET;
    }
    return EMUNGE_SUCCESS;

}


/**
 *  Receive a message over [m]'s bound socket, unpacking and storing it in the
 *  previously-created [m].
 *
 *  If [type] is specified (not MUNGE_MSG_UNDEF) and does not match the
 *  received header type, discard the message and return an error.
 *
 *  Reject a zero-length body, and (if [maxlen] > 0) a body larger than
 *  [maxlen] bytes, with EMUNGE_BAD_LENGTH.
 *
 *  Return a standard munge error code.
 */
munge_err_t
m_msg_recv (m_msg_t m, m_msg_type_t type, size_t maxlen)
{
    int n, nrecv;
    uint8_t hdr[MUNGE_MSG_HDR_SIZE];
    struct timeval tv;
    munge_err_t e = EMUNGE_SUCCESS;

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
    nrecv = sizeof hdr;
    if ((errno = 0, n = fd_timed_read_n (m->sd, hdr, nrecv, &tv, 1)) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to receive message header: %s",
                strerror (errno)));
        return EMUNGE_SOCKET;
    }
    else if (errno == ETIMEDOUT) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to receive message header: Timed-out"));
        return EMUNGE_SOCKET;
    }
    else if (n != nrecv) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message header: %d of %d bytes",
            n, nrecv));
        return EMUNGE_SOCKET;
    }
    else if (_msg_unpack (m, MUNGE_MSG_HDR, hdr, sizeof hdr)
            != EMUNGE_SUCCESS) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to unpack message header"));
        return EMUNGE_SOCKET;
    }
    else if ((type != MUNGE_MSG_UNDEF) && (m->type != type)) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received unexpected message type: wanted %d, got %d",
                type, m->type));
        return EMUNGE_SOCKET;
    }
    else if (m->pkt_len == 0) {
        m_msg_set_err (m, EMUNGE_BAD_LENGTH,
            strdup ("Failed to receive message: Size 0 is invalid"));
        return EMUNGE_BAD_LENGTH;
    }
    else if ((maxlen > 0) && (m->pkt_len > maxlen)) {
        m_msg_set_err (m, EMUNGE_BAD_LENGTH,
            strdupf ("Failed to receive message: Size %" PRIu32
                " exceeded maximum of %zu", m->pkt_len, maxlen));
        return EMUNGE_BAD_LENGTH;
    }
    else if (!(m->pkt = malloc (m->pkt_len))) {
        m_msg_set_err (m, EMUNGE_NO_MEMORY,
            strdupf ("Failed to allocate %" PRIu32
                " bytes for receiving message", m->pkt_len));
        return EMUNGE_NO_MEMORY;
    }
    else if ((errno = 0,
              n = fd_timed_read_n (m->sd, m->pkt, m->pkt_len, &tv, 1)) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to receive message body: %s", strerror (errno)));
        e = EMUNGE_SOCKET;
    }
    else if (errno == ETIMEDOUT) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to receive message body: Timed-out"));
        e = EMUNGE_SOCKET;
    }
    else if ((uint32_t) n != m->pkt_len) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message body: %d of %" PRIu32
                " bytes", n, m->pkt_len));
        e = EMUNGE_SOCKET;
    }
    else if (_msg_unpack (m, m->type, m->pkt, m->pkt_len) != EMUNGE_SUCCESS) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Failed to unpack message body"));
        e = EMUNGE_SOCKET;
    }
    /*  Discard the packed message.
     */
    assert (m->pkt_len > 0);
    memwipe_and_free (m->pkt, (size_t) m->pkt_len);
    m->pkt = NULL;
    m->pkt_len = 0;
    assert (m->pkt_is_copy == 0);
    return e;
}


/**
 *  Set an error code [e] and error string [s] if an error is not already set.
 *
 *  Return -1 always and consume [s].
 */
int
m_msg_set_err (m_msg_t m, munge_err_t e, char *s)
{
    assert (m != NULL);

    if ((m->error_num == EMUNGE_SUCCESS) && (e != EMUNGE_SUCCESS)) {
        const char *src = s ? s : munge_strerror (e);
        char buf[UINT8_MAX];

        assert (m->error_str == NULL);
        assert (m->error_len == 0);
        assert (m->error_is_copy == 0);

        if (memccpy (buf, src, '\0', sizeof buf) == NULL) {
            buf[sizeof buf - 1] = '\0';
        }
        m->error_num = e;
        m->error_str = strdup (buf);
        m->error_len = m->error_str ? strlen (m->error_str) + 1 : 0;
    }
    free (s);
    return -1;
}


/******************************************************************************
 *  Private Functions
 *****************************************************************************/

/**
 *  Set [tv] to the current time advanced by [msecs] milliseconds.
 *
 *  On erro, set [tv] to zero, a past absolute deadline that fd_timed_*()
 *  callers treat as an immediate timeout.
 */
static void
_get_timeval (struct timeval *tv, int msecs)
{
    assert (tv != NULL);

    if (gettimeofday (tv, NULL) < 0) {
        tv->tv_sec = tv->tv_usec = 0;
    }
    else if (msecs > 0) {
        tv->tv_sec += msecs / 1000;
        tv->tv_usec += (msecs % 1000) * 1000;
        if (tv->tv_usec >= 1000000) {
            tv->tv_sec += tv->tv_usec / 1000000;
            tv->tv_usec %= 1000000;
        }
    }
}


/**
 *  Compute the number of bytes needed to pack the message [m] of type [type].
 *
 *  Return the packed length (> 0), or -1 on error.
 */
static int
_msg_length (m_msg_t m, m_msg_type_t type)
{
    uint64_t n = 0;

    assert (m != NULL);

    switch (type) {
        case MUNGE_MSG_HDR:
            n += sizeof (m_msg_magic_t);
            n += sizeof (m_msg_version_t);
            n += sizeof m->type;
            n += sizeof m->retry;
            n += sizeof m->pkt_len;
            break;
        case MUNGE_MSG_ENC_REQ:
            n += sizeof m->cipher;
            n += sizeof m->mac;
            n += sizeof m->zip;
            n += sizeof m->realm_len;
            n += m->realm_len;
            n += sizeof m->ttl;
            n += sizeof m->auth_uid;
            n += sizeof m->auth_gid;
            n += sizeof m->data_len;
            n += m->data_len;
            break;
        case MUNGE_MSG_ENC_RSP:
            n += sizeof m->error_num;
            n += sizeof m->error_len;
            n += m->error_len;
            n += sizeof m->data_len;
            n += m->data_len;
            break;
        case MUNGE_MSG_DEC_REQ:
            n += sizeof m->data_len;
            n += m->data_len;
            break;
        case MUNGE_MSG_DEC_RSP:
            n += sizeof m->error_num;
            n += sizeof m->error_len;
            n += m->error_len;
            n += sizeof m->cipher;
            n += sizeof m->mac;
            n += sizeof m->zip;
            n += sizeof m->realm_len;
            n += m->realm_len;
            n += sizeof m->ttl;
            n += sizeof m->addr_len;
            n += m->addr_len;
            n += sizeof m->time0;
            n += sizeof m->time1;
            n += sizeof m->cred_uid;
            n += sizeof m->cred_gid;
            n += sizeof m->auth_uid;
            n += sizeof m->auth_gid;
            n += sizeof m->data_len;
            n += m->data_len;
            break;
        case MUNGE_MSG_AUTH_FD_REQ:
            n += sizeof m->auth_s_len;
            n += m->auth_s_len;
            n += sizeof m->auth_c_len;
            n += m->auth_c_len;
            break;
        default:
            return -1;
    }
    if (n > INT_MAX) {
        return -1;
    }
    return (int) n;
}


/**
 *  Pack the message [m] of type [type] into the buffer [dst] of length
 *  [dstlen] for transport across the munge socket.
 *
 *  Return a standard munge error code.
 */
static munge_err_t
_msg_pack (m_msg_t m, m_msg_type_t type, void *dst, int dstlen)
{
    m_msg_magic_t magic = MUNGE_MSG_MAGIC;
    m_msg_version_t version = MUNGE_MSG_VERSION;
    void *p = dst;
    void *q = (unsigned char *) dst + dstlen;

    assert (m != NULL);

    switch (type) {
        case MUNGE_MSG_HDR:
            if      (_pack (&p, &magic, sizeof magic, q) < 0) ;
            else if (_pack (&p, &version, sizeof version, q) < 0) ;
            else if (_pack (&p, &m->type, sizeof m->type, q) < 0) ;
            else if (_pack (&p, &m->retry, sizeof m->retry, q) < 0) ;
            else if (_pack (&p, &m->pkt_len, sizeof m->pkt_len, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_REQ:
            if      (_pack (&p, &m->cipher, sizeof m->cipher, q) < 0) ;
            else if (_pack (&p, &m->mac, sizeof m->mac, q) < 0) ;
            else if (_pack (&p, &m->zip, sizeof m->zip, q) < 0) ;
            else if (_pack (&p, &m->realm_len, sizeof m->realm_len, q) < 0) ;
            else if (_copy (p, m->realm_str, m->realm_len, &p, q) < 0) ;
            else if (_pack (&p, &m->ttl, sizeof m->ttl, q) < 0) ;
            else if (_pack (&p, &m->auth_uid, sizeof m->auth_uid, q) < 0) ;
            else if (_pack (&p, &m->auth_gid, sizeof m->auth_gid, q) < 0) ;
            else if (_pack (&p, &m->data_len, sizeof m->data_len, q) < 0) ;
            else if (_copy (p, m->data, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_RSP:
            if      (_pack (&p, &m->error_num, sizeof m->error_num, q) < 0) ;
            else if (_pack (&p, &m->error_len, sizeof m->error_len, q) < 0) ;
            else if (_copy (p, m->error_str, m->error_len, &p, q) < 0) ;
            else if (_pack (&p, &m->data_len, sizeof m->data_len, q) < 0) ;
            else if (_copy (p, m->data, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_REQ:
            if      (_pack (&p, &m->data_len, sizeof m->data_len, q) < 0) ;
            else if (_copy (p, m->data, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_RSP:
            if      (_pack (&p, &m->error_num, sizeof m->error_num, q) < 0) ;
            else if (_pack (&p, &m->error_len, sizeof m->error_len, q) < 0) ;
            else if (_copy (p, m->error_str, m->error_len, &p, q) < 0) ;
            else if (_pack (&p, &m->cipher, sizeof m->cipher, q) < 0) ;
            else if (_pack (&p, &m->mac, sizeof m->mac, q) < 0) ;
            else if (_pack (&p, &m->zip, sizeof m->zip, q) < 0) ;
            else if (_pack (&p, &m->realm_len, sizeof m->realm_len, q) < 0) ;
            else if (_copy (p, m->realm_str, m->realm_len, &p, q) < 0) ;
            else if (_pack (&p, &m->ttl, sizeof m->ttl, q) < 0) ;
            else if (_pack (&p, &m->addr_len, sizeof m->addr_len, q) < 0) ;
            else if (_copy (p, &m->addr, m->addr_len, &p, q) < 0) ;
            else if (_pack (&p, &m->time0, sizeof m->time0, q) < 0) ;
            else if (_pack (&p, &m->time1, sizeof m->time1, q) < 0) ;
            else if (_pack (&p, &m->cred_uid, sizeof m->cred_uid, q) < 0) ;
            else if (_pack (&p, &m->cred_gid, sizeof m->cred_gid, q) < 0) ;
            else if (_pack (&p, &m->auth_uid, sizeof m->auth_uid, q) < 0) ;
            else if (_pack (&p, &m->auth_gid, sizeof m->auth_gid, q) < 0) ;
            else if (_pack (&p, &m->data_len, sizeof m->data_len, q) < 0) ;
            else if (_copy (p, m->data, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_AUTH_FD_REQ:
            if      (_pack (&p, &m->auth_s_len, sizeof m->auth_s_len, q) < 0) ;
            else if (_copy (p, m->auth_s_str, m->auth_s_len, &p, q) < 0) ;
            else if (_pack (&p, &m->auth_c_len, sizeof m->auth_c_len, q) < 0) ;
            else if (_copy (p, m->auth_c_str, m->auth_c_len, &p, q) < 0) ;
            else break;
            goto err;
        default:
            goto err;
    }
    return EMUNGE_SUCCESS;

err:
    m_msg_set_err (m, EMUNGE_SNAFU,
        strdupf ("Failed to pack message type %d", type));
    return EMUNGE_SNAFU;
}


/**
 *  Unpack the message [m] of type [type] from the buffer [src] of length
 *  [srclen] received across the munge socket.
 *
 *  Return a standard munge error code.
 */
static munge_err_t
_msg_unpack (m_msg_t m, m_msg_type_t type, const void *src, int srclen)
{
    m_msg_magic_t magic;
    m_msg_version_t version;
    void *p = (void *) src;
    void *q = (unsigned char *) src + srclen;

    assert (m != NULL);

    switch (type) {
        case MUNGE_MSG_HDR:
            if      (_unpack (&magic, &p, sizeof magic, q) < 0) ;
            else if (_unpack (&version, &p, sizeof version, q) < 0) ;
            else if (_unpack (&m->type, &p, sizeof m->type, q) < 0) ;
            else if (_unpack (&m->retry, &p, sizeof m->retry, q) < 0) ;
            else if (_unpack (&m->pkt_len, &p, sizeof m->pkt_len, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_REQ:
            if      (_unpack (&m->cipher, &p, sizeof m->cipher, q) < 0) ;
            else if (_unpack (&m->mac, &p, sizeof m->mac, q) < 0) ;
            else if (_unpack (&m->zip, &p, sizeof m->zip, q) < 0) ;
            else if (_unpack (&m->realm_len, &p, sizeof m->realm_len, q) < 0) ;
            else if (_alloc ((vpp) &m->realm_str, m->realm_len) < 0) goto nomem;
            else if (_copy (m->realm_str, p, m->realm_len, &p, q) < 0) ;
            else if (_unpack (&m->ttl, &p, sizeof m->ttl, q) < 0) ;
            else if (_unpack (&m->auth_uid, &p, sizeof m->auth_uid, q) < 0) ;
            else if (_unpack (&m->auth_gid, &p, sizeof m->auth_gid, q) < 0) ;
            else if (_unpack (&m->data_len, &p, sizeof m->data_len, q) < 0) ;
            else if (_alloc (&m->data, m->data_len) < 0) goto nomem;
            else if (_copy (m->data, p, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_ENC_RSP:
            if      (_unpack (&m->error_num, &p, sizeof m->error_num, q) < 0) ;
            else if (_unpack (&m->error_len, &p, sizeof m->error_len, q) < 0) ;
            else if (_alloc ((vpp) &m->error_str, m->error_len) < 0) goto nomem;
            else if (_copy (m->error_str, p, m->error_len, &p, q) < 0) ;
            else if (_unpack (&m->data_len, &p, sizeof m->data_len, q) < 0) ;
            else if (_alloc (&m->data, m->data_len) < 0) goto nomem;
            else if (_copy (m->data, p, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_REQ:
            if      (_unpack (&m->data_len, &p, sizeof m->data_len, q) < 0) ;
            else if (_alloc (&m->data, m->data_len) < 0) goto nomem;
            else if (_copy (m->data, p, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_DEC_RSP:
            if      (_unpack (&m->error_num, &p, sizeof m->error_num, q) < 0) ;
            else if (_unpack (&m->error_len, &p, sizeof m->error_len, q) < 0) ;
            else if (_alloc ((vpp) &m->error_str, m->error_len) < 0) goto nomem;
            else if (_copy (m->error_str, p, m->error_len, &p, q) < 0) ;
            else if (_unpack (&m->cipher, &p, sizeof m->cipher, q) < 0) ;
            else if (_unpack (&m->mac, &p, sizeof m->mac, q) < 0) ;
            else if (_unpack (&m->zip, &p, sizeof m->zip, q) < 0) ;
            else if (_unpack (&m->realm_len, &p, sizeof m->realm_len, q) < 0) ;
            else if (_alloc ((vpp) &m->realm_str, m->realm_len) < 0) goto nomem;
            else if (_copy (m->realm_str, p, m->realm_len, &p, q) < 0) ;
            else if (_unpack (&m->ttl, &p, sizeof m->ttl, q) < 0) ;
            else if (_unpack (&m->addr_len, &p, sizeof m->addr_len, q) < 0) ;
            else if (m->addr_len > sizeof m->addr) goto err;
            else if (_copy (&m->addr, p, m->addr_len, &p, q) < 0) ;
            else if (_unpack (&m->time0, &p, sizeof m->time0, q) < 0) ;
            else if (_unpack (&m->time1, &p, sizeof m->time1, q) < 0) ;
            else if (_unpack (&m->cred_uid, &p, sizeof m->cred_uid, q) < 0) ;
            else if (_unpack (&m->cred_gid, &p, sizeof m->cred_gid, q) < 0) ;
            else if (_unpack (&m->auth_uid, &p, sizeof m->auth_uid, q) < 0) ;
            else if (_unpack (&m->auth_gid, &p, sizeof m->auth_gid, q) < 0) ;
            else if (_unpack (&m->data_len, &p, sizeof m->data_len, q) < 0) ;
            else if (_alloc (&m->data, m->data_len) < 0) goto nomem;
            else if (_copy (m->data, p, m->data_len, &p, q) < 0) ;
            else break;
            goto err;
        case MUNGE_MSG_AUTH_FD_REQ:
            if      (_unpack (&m->auth_s_len, &p, sizeof m->auth_s_len, q) < 0) ;
            else if (_alloc ((vpp) &m->auth_s_str, m->auth_s_len) < 0) goto nomem;
            else if (_copy (m->auth_s_str, p, m->auth_s_len, &p, q) < 0) ;
            else if (_unpack (&m->auth_c_len, &p, sizeof m->auth_c_len, q) < 0) ;
            else if (_alloc ((vpp) &m->auth_c_str, m->auth_c_len) < 0) goto nomem;
            else if (_copy (m->auth_c_str, p, m->auth_c_len, &p, q) < 0) ;
            else break;
            goto err;
        default:
            goto err;
    }
    if (p != (unsigned char *) src + srclen) {
        m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Unpacked wrong number of bytes for message type %d",
            type));
        return EMUNGE_SNAFU;
    }
    if (type == MUNGE_MSG_HDR) {
        if (magic != MUNGE_MSG_MAGIC) {
            m_msg_set_err (m, EMUNGE_SOCKET,
                strdupf ("Received invalid message magic %" PRIu32, magic));
            return EMUNGE_SOCKET;
        }
        else if (version != MUNGE_MSG_VERSION) {
            m_msg_set_err (m, EMUNGE_SOCKET,
                strdupf ("Received invalid message version %d", version));
            return EMUNGE_SOCKET;
        }
    }
    return EMUNGE_SUCCESS;

err:
    m_msg_set_err (m, EMUNGE_SNAFU,
        strdupf ("Failed to unpack message type %d", type));
    return EMUNGE_SNAFU;

nomem:
    m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL);
    return EMUNGE_NO_MEMORY;
}


/**
 *  Allocate [len]+1 bytes and store the result at [*pdst].
 *
 *  The trailing byte at [len] is set to NUL so a string field remains
 *  null-terminated even when the copied wire data is not.
 *
 *  Return the number of bytes requested ([len]), or -1 on error.
 */
static int
_alloc (void **pdst, int len)
{
    unsigned char *p;

    assert (pdst != NULL);
    assert (*pdst == NULL);             /* must not overwrite a live pointer */

    if (len < 0) {
        return -1;
    }
    if (len == 0) {                     /* valid empty field, no allocation */
        return 0;
    }
    /*  Allocate one extra byte and set it to NUL so a string field stays
     *  terminated even when the copied wire data is not.  The terminator is
     *  set here in the allocator, rather than at the copy: _copy() runs
     *  without a preceding _alloc() in some cases, so it has no terminator
     *  slot to rely on.  Callers copy exactly [len] bytes into [0,len),
     *  leaving this byte at [len] intact.
     */
    if (!(p = malloc (len + 1))) {
        return -1;
    }
    p[len] = '\0';
    *pdst = p;
    return len;
}


/**
 *  Copy [len] bytes from [src] to [dst], requiring [len] bytes to be available
 *  in [*pfirst, last) and then advancing the cursor [*pfirst] by [len].
 *
 *  Return the number of bytes copied, or -1 on error.
 *
 *  Note: [len] is validated at runtime because it may derive from
 *  peer-supplied message fields; the pointer arguments are caller-controlled
 *  invariants and are checked with assert().
 */
static int
_copy (void *dst, const void *src, int len, void **pfirst, const void *last)
{
    if (len < 0) {
        return -1;
    }
    assert (pfirst != NULL);
    assert (*pfirst != NULL);
    assert (last != NULL);
    if ((unsigned char *) *pfirst + len > (unsigned char *) last) {
        return -1;
    }
    if (len > 0) {
        assert (dst != NULL);
        assert (src != NULL);
        memcpy (dst, src, len);
        *pfirst = (unsigned char *) *pfirst + len;
    }
    return len;
}


/**
 *  Pack the [src] scalar of [len] bytes into the buffer at [*pdst] in
 *  MSB-first order, then advance [*pdst] by [len].
 *
 *  Require [len] bytes to fit in the buffer bounded by [last]; [last] must be
 *  non-NULL.  [len] must be a supported scalar width.
 *
 *  Return the number of bytes packed, or -1 on error.
 */
static int
_pack (void **pdst, const void *src, int len, const void *last)
{
    void *dst;
    uint16_t u16;
    uint32_t u32;

    assert (pdst != NULL);
    assert (src != NULL);
    assert (len >= 0);
    assert (last != NULL);

    dst = *pdst;
    if ((unsigned char *) dst + len > (unsigned char *) last) {
        return -1;
    }
    switch (len) {
        case sizeof (uint8_t):
            * (uint8_t *) dst = * (uint8_t *) src;
            break;
        case sizeof (uint16_t):
            u16 = htons (* (uint16_t *) src);
            memcpy (dst, &u16, len);
            break;
        case sizeof (uint32_t):
            u32 = htonl (* (uint32_t *) src);
            memcpy (dst, &u32, len);
            break;
        default:
            return -1;
    }
    *pdst = (unsigned char *) dst + len;
    return len;
}


/**
 *  Unpack [len] bytes in MSB-first order from the buffer at [*psrc] into the
 *  [dst] scalar, then advance [*psrc] by [len].
 *
 *  Require [len] bytes to exist in the buffer bounded by [last]; [last] must
 *  be non-NULL.  [len] must be a supported scalar width.
 *
 *  Return the number of bytes unpacked, or -1 on error.
 */
static int
_unpack (void *dst, void **psrc, int len, const void *last)
{
    void *src;
    uint16_t u16;
    uint32_t u32;

    assert (dst != NULL);
    assert (psrc != NULL);
    assert (len >= 0);
    assert (last != NULL);

    src = *psrc;
    if ((unsigned char *) src + len > (unsigned char *) last) {
        return -1;
    }
    switch (len) {
        case sizeof (uint8_t):
            * (uint8_t *) dst = * (uint8_t *) src;
            break;
        case sizeof (uint16_t):
            memcpy (&u16, src, len);
            * (uint16_t *) dst = ntohs (u16);
            break;
        case sizeof (uint32_t):
            memcpy (&u32, src, len);
            * (uint32_t *) dst = ntohl (u32);
            break;
        default:
            return -1;
    }
    *psrc = (unsigned char *) src + len;
    return len;
}
