/*****************************************************************************
 *  $Id: msg.c,v 1.1 2004/11/24 00:21:57 dun Exp $
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
#include <errno.h>
#include <munge.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include "fd.h"
#include "msg.h"
#include "munge_defs.h"
#include "str.h"


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
msg_create (msg_t *pm, int sd)
{
/*  Creates a message bound to the socket [sd], returning it via the [pm] ptr.
 *  Returns a standard munge error code.
 */
    msg_t m;

    assert (pm != NULL);

    if (!(m = malloc (sizeof (struct msg)))) {
        *pm = NULL;
        return (EMUNGE_NO_MEMORY);
    }
    /*  Initialize ints to 0, ptrs to NULL.
     */
    memset (m, 0, sizeof (struct msg));

    m->sd = sd;
    m->head.magic = MUNGE_MSG_MAGIC;
    m->head.version = MUNGE_MSG_VERSION;
    m->head.type = MUNGE_MSG_UNKNOWN;
    m->errnum = EMUNGE_SUCCESS;

    *pm = m;
    return (EMUNGE_SUCCESS);
}


void
msg_destroy (msg_t m)
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
msg_send (msg_t m, int maxlen)
{
/*  Sends the message [m] to the recipient at the other end of the
 *    already-specified socket.
 *  If [maxlen] > 0, messages larger than this value will be discarded and
 *    a munge error will be returned to the caller.
 *  This message contains a common header and a version-specific body.
 *  Returns a standard munge error code.
 */
    struct msg_v1 *m1;
    int            i, n, nsend;
    int            iov_num;
    struct iovec   iov[5];

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (m->head.magic == MUNGE_MSG_MAGIC);
    assert (m->head.version == MUNGE_MSG_VERSION);
    assert (m->pbody != NULL);

    m1 = m->pbody;
    m->head.length = sizeof (*m1);
    m->head.length += m1->realm_len;
    m->head.length += m1->data_len;
    m->head.length += m1->error_len;

    iov[0].iov_base = (char *) &(m->head);
    iov[0].iov_len = sizeof (m->head);

    iov[1].iov_base = (char *) m1;
    iov[1].iov_len = sizeof (*m1);

    iov[2].iov_base = m1->realm;
    iov[2].iov_len = m1->realm_len;

    iov[3].iov_base = m1->data;
    iov[3].iov_len = m1->data_len;

    iov[4].iov_base = m1->error_str;
    iov[4].iov_len = m1->error_len;

    iov_num = sizeof (iov) / sizeof (iov[0]);
    for (i=0, nsend=0; i < iov_num; i++) {
        nsend += iov[i].iov_len;
    }
    /*  An EINTR should only occur before any data is transferred.
     *    As such, it should be jiggy to restart the whole writev() if needed.
     */
again:
    if ((n = writev (m->sd, iov, iov_num)) < 0) {
        if (errno == EINTR)
            goto again;
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to send message: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    /*  Normally, the test here for exceeding the message length would be
     *    placed before the write to prevent an error that will surely happen.
     *    But the reason it is placed here after the writev() is to allow the
     *    daemon to log the attempt to exceed the maximum message length.
     *    The daemon will abort its read after having read only the
     *    msg_head struct.
     */
    if ((maxlen > 0) && (m->head.length > maxlen)) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to send message: length %d exceeds max of %d",
                m->head.length, maxlen));
        return (EMUNGE_BAD_LENGTH);
    }
    if (n != nsend) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Sent incomplete message: %d of %d bytes", n, nsend));
        return (EMUNGE_SOCKET);
    }
    return (EMUNGE_SUCCESS);
}


munge_err_t
msg_recv (msg_t m, int maxlen)
{
/*  Receives a message from the sender at the other end of the already-
 *    specified socket.  This message is stored in the already-allocated [m].
 *  If [maxlen] > 0, messages larger than this value will be discarded and
 *    a munge error will be returned to the caller.
 *  Returns a standard munge error code.
 */
    struct msg_v1 *m1;
    int            n, nrecv;

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (m->pbody == NULL);

    /*  Read and validate the message header.
     */
    nrecv = sizeof (m->head);
    if ((n = fd_read_n (m->sd, &(m->head), nrecv)) < 0) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to receive message header: %s",
                strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    else if (n == 0) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received empty message"));
        return (EMUNGE_SOCKET);
    }
    else if (n != nrecv) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message header: %d of %d bytes",
            n, nrecv));
        return (EMUNGE_SOCKET);
    }
    else if (m->head.magic != MUNGE_MSG_MAGIC) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received invalid message magic %d", m->head.magic));
        return (EMUNGE_SOCKET);
    }
    else if (m->head.version != MUNGE_MSG_VERSION) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received invalid message version %d", m->head.version));
        return (EMUNGE_SOCKET);
    }
    else if (m->head.length < sizeof (struct msg_v1)) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received invalid message length %d", m->head.length));
        return (EMUNGE_SOCKET);
    }
    else if ((maxlen > 0) && (m->head.length > maxlen)) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received message length %d exceeding max of %d",
                m->head.length, maxlen));
        return (EMUNGE_BAD_LENGTH);
    }
    /*  Read the version-specific message body.
     *  Reserve space for a terminating NUL character.  This NUL is not
     *    received across the socket, but appended afterwards.
     */
    m->pbody_len = m->head.length + 1;
    if (!(m->pbody = malloc (m->pbody_len))) {
        msg_set_err (m, EMUNGE_NO_MEMORY,
            strdupf ("Unable to malloc %d bytes for message", m->pbody_len));
        return (EMUNGE_NO_MEMORY);
    }
    nrecv = m->head.length;
    if ((n = fd_read_n (m->sd, m->pbody, nrecv)) < 0) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to receive message: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (n != nrecv) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received incomplete message: %d of %d bytes", n, nrecv));
        return (EMUNGE_SOCKET);
    }
    m1 = m->pbody;
    n = sizeof (*m1);
    /*
     *  Locate the realm string (if present) within the message body.
     *    It immediately follows the msg_v1 struct.
     */
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
    /*  Locate the error string (if present) within the message body.
     *    It immediately follows the data segment.
     */
    if (m1->error_len > 0) {
        m1->error_str = ((char *) m1) + n;
        n += m1->error_len;
    }
    else {
        m1->error_str = NULL;
    }
    /*  Validate the length of the version-specific message body.
     */
    if (n != m->head.length) {
        msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Received unexpected message length: %d of %d bytes",
                m->head.length, n));
        return (EMUNGE_SOCKET);
    }
    /*  Append the terminating NUL character now that the length is verified.
     */
    ((char *) m->pbody)[m->head.length] = '\0';
    /*
     *  If an error message was returned, copy it into the message metadata.
     */
    m->errnum = m1->error_num;
    if (m1->error_str) {
        assert (m1->error_len > 0);
        assert (m->errstr == NULL);
        m->errstr = strdup (m1->error_str);
    }
    return (EMUNGE_SUCCESS);
}


int
msg_set_err (msg_t m, munge_err_t e, char *s)
{
/*  Set an error code [e] and string [s] if an error condition
 *    does not already exist (ie, m->errnum == EMUNGE_SUCCESS).
 *    Thus, if multiple errors are set, only the first one is reported.
 *  If [s] is not NULL, that string (and _not_ a copy) will be stored
 *    and later free()'d by the message destructor; if [s] is NULL,
 *    munge_strerror() will be used to obtain a descriptive string.
 *  Always returns -1 and consumes [s].
 *
 *  Note that the error condition (status code and message string) is stored
 *    within the msg 'errnum' & 'errmsg' variables.  When the message
 *    is transmitted over the socket from server to client, these are passed
 *    via the version-specific message format as appropriate.
 */
    assert (m != NULL);

    if ((m->errnum == EMUNGE_SUCCESS) && (e != EMUNGE_SUCCESS)) {
        m->errnum = e;
        assert (m->errstr == NULL);
        m->errstr = (s != NULL) ? s : strdup (munge_strerror (e));;
    }
    else if (s) {
        free (s);
    }
    /*  "Screw you guys, I'm goin' home." -ecartman
     */
    return (-1);
}
