/*****************************************************************************
 *  $Id: munge_msg.c,v 1.12 2003/12/19 00:18:25 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
#include <errno.h>
#include <munge.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include "munge_msg.h"
#include "common.h"


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_err_t
_munge_msg_create (munge_msg_t *pm, int sd)
{
/*  Creates a message bound to the socket [sd], returning it via the [pm] ptr.
 *  Returns a standard munge error code.
 */
    munge_msg_t m;

    assert (pm != NULL);

    if (!(m = malloc (sizeof (struct munge_msg)))) {
        *pm = NULL;
        return (EMUNGE_NO_MEMORY);
    }
    /*  Initialize ints to 0, ptrs to NULL.
     */
    memset (m, 0, sizeof (struct munge_msg));

    _munge_msg_reset (m);
    m->sd = sd;
    m->status = EMUNGE_SUCCESS;

    *pm = m;
    return (EMUNGE_SUCCESS);
}


void
_munge_msg_destroy (munge_msg_t m)
{
/*  Destroys the message [m].
 */
    assert (m != NULL);

    if (m->sd >= 0) {
        close (m->sd);                  /* ignoring errors on close() */
        m->sd = -1;
    }
    if (m->pbody) {
        assert (m->pbody_len > 0);
        memset (m->pbody, 0, m->pbody_len);
        free (m->pbody);
    }
    if (m->errstr) {
        memset (m->errstr, 0, strlen (m->errstr));
        free (m->errstr);
    }
    memset (m, 0, sizeof (*m));
    free (m);
    return;
}


munge_err_t
_munge_msg_send (munge_msg_t m)
{
/*  Sends the message [m] to the recipient at the other end of the
 *    already-specified socket.
 *  This message contains a common header and a version-specific body.
 *    Currently, only v1 messages are used.
 *  Returns a standard munge error code.
 */
    int                  n, l;
    struct munge_msg_v1 *m1;
    struct iovec         iov[4];

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (m->head.magic == MUNGE_MSG_MAGIC);
    assert (m->head.version == MUNGE_MSG_VERSION);
    assert (m->pbody != NULL);

    if (m->head.version != 1) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to send unsupported message version %d",
            m->head.version));
        return (EMUNGE_SOCKET);
    }
    m1 = m->pbody;
    m->head.length = sizeof (*m1);
    m->head.length += m1->realm_len;
    m->head.length += m1->data_len;

    iov[0].iov_base = &(m->head);
    iov[0].iov_len = sizeof (m->head);

    iov[1].iov_base = m1;
    iov[1].iov_len = sizeof (*m1);

    iov[2].iov_base = m1->realm;
    iov[2].iov_len = m1->realm_len;

    iov[3].iov_base = m1->data;
    iov[3].iov_len = m1->data_len;

    n = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len + iov[3].iov_len;

again:
    if ((l = writev (m->sd, iov, 4)) < 0) {
        if (errno == EINTR)
            goto again;
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to send message: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (l != n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Sent incomplete message: %d of %d bytes", l, n));
        return (EMUNGE_SOCKET);
    }
    return (EMUNGE_SUCCESS);
}


munge_err_t
_munge_msg_recv (munge_msg_t m)
{
/*  Receives a message from the sender at the other end of the already-
 *    specified socket.  This message is stored in the already-allocated [m].
 *  Returns a standard munge error code.
 */
    int                  n, l;
    struct munge_msg_v1 *m1;

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (m->pbody == NULL);

    /*  Read and validate the message header.
     */
    n = sizeof (m->head);
    if ((l = fd_read_n (m->sd, &(m->head), n)) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to receive message header: %s",
                strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (l != n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message header: %d of %d bytes",
            l, n));
        return (EMUNGE_SOCKET);
    }
    if (m->head.magic != MUNGE_MSG_MAGIC) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received invalid message magic %d", m->head.magic));
        return (EMUNGE_SOCKET);
    }
    if (m->head.version > MUNGE_MSG_VERSION) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received invalid message version %d", m->head.version));
        return (EMUNGE_SOCKET);
    }
    if (m->head.length <= 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received invalid message length %d", m->head.length));
        return (EMUNGE_SOCKET);
    }
    /*  Read the version-specific message body.
     *  Reserve space for a terminating NUL character.  This NUL is not
     *    transmitted across the socket, but will be appended afterwards.
     */
    n = m->head.length + 1;
    if (!(m->pbody = malloc (n))) {
        _munge_msg_set_err (m, EMUNGE_NO_MEMORY,
            strdupf ("Unable to malloc %d bytes for message", n));
        return (EMUNGE_NO_MEMORY);
    }
    m->pbody_len = n;
    n = m->head.length;
    if ((l = fd_read_n (m->sd, m->pbody, n)) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to receive message: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (l != n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message: %d of %d bytes", l, n));
        return (EMUNGE_SOCKET);
    }
    m1 = m->pbody;
    /*
     *  Locate the realm string (if present) within the message body.
     *    It immediately follows the munge_msg_v1 struct.
     */
    n = sizeof (*m1);
    if (m1->realm_len > 0) {
        m1->realm = ((char *) m1) + n;
        n += m1->realm_len;
    }
    else {
        m1->realm = NULL;
    }
    /*  Locate the message payload data (if present) within the message body.
     *    It immediately follows the realm string.
     */
    if (m1->data_len > 0) {
        m1->data = ((char *) m1) + n;
        n += m1->data_len;
    }
    else {
        m1->data = NULL;
    }
    /*  Validate the length of the version-specific message body.
     */
    if (n != m->head.length) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received unexpected message length: %d of %d bytes",
                m->head.length, n));
        return (EMUNGE_SOCKET);
    }
    /*  Append the terminating NUL character now that the length is verified.
     */
    ((char *) m->pbody)[m->head.length] = '\0';
    /*
     *  If an error message was returned, copy the error condition
     *    into the message metadata.
     */
    if (m->head.type == MUNGE_MSG_ERROR) {
        m->status = m1->errnum;
        m->errstr = strdup (m1->data);
    }
    return (EMUNGE_SUCCESS);
}


munge_err_t
_munge_msg_reset (munge_msg_t m)
{
/*  Resets the message struct [m] for a new message.
 *  This allows the struct used for receiving the request to be re-used
 *    for sending the response without having to re-allocate everything.
 *  It seemed like a good idea at the time.
 *  Returns a standard munge error code.
 */
    assert (m != NULL);

    m->head.magic = MUNGE_MSG_MAGIC;
    m->head.version = MUNGE_MSG_VERSION;
    m->head.type = MUNGE_MSG_UNKNOWN;
    m->head.length = 0;
    if (m->pbody) {
        assert (m->pbody_len > 0);
        memset (m->pbody, 0, m->pbody_len);
        free (m->pbody);
        m->pbody_len = 0;
        m->pbody = NULL;                /* Sherman, set the Wayback Machine */
    }
    return (EMUNGE_SUCCESS);
}


int
_munge_msg_set_err (munge_msg_t m, munge_err_t e, char *s)
{
/*  Set an error code [e] and string [s] if an error condition
 *    does not already exist (ie, m->status == EMUNGE_SUCCESS).
 *    Thus, if multiple errors are set, only the first one is reported.
 *  If [s] is not NULL, that string (and _not_ a copy) will be stored
 *    and later free()'d by the message destructor; if [s] is NULL,
 *    munge_strerror() will be used.
 *  Always returns -1.
 */
    assert (m != NULL);

    /*  Do nothing if an error does not exist or an error has already been set.
     */
    if ((e == EMUNGE_SUCCESS) || (m->status != EMUNGE_SUCCESS)) {
        if (s) {
            free (s);
        }
    }
    else {
        m->status = e;
        assert (m->errstr == NULL);
        m->errstr = (s != NULL) ? s : strdup (munge_strerror (e));;
    }
    /*  "Screw you guys, I'm goin' home." -ecartman
     */
    return (-1);
}
