/*****************************************************************************
 *  $Id: munge_msg.c,v 1.2 2003/04/18 23:20:18 dun Exp $
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
#include "munge_msg.h"
#include "common.h"


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_err_t
_munge_msg_create (munge_msg_t *pm, int sd)
{
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
/*  The message sent across the socket contains a common message header
 *    and a version-specific message body.
 *  Currently, only v1 messages are used.
 */
    int n;
    struct munge_msg_v1 *m1;

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
    /*
     *  FIXME: Replace multiple write()s with a single writev()?
     */
    n = sizeof (m->head);
    if (fd_write_n (m->sd, &(m->head), n) < n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to write message header (%d bytes)", n));
        return (EMUNGE_SOCKET);
    }
    n = sizeof (*m1);
    if (fd_write_n (m->sd, m1, n) < n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to write v1 message body (%d bytes)", n));
        return (EMUNGE_SOCKET);
    }
    n = m1->realm_len;
    if ((n > 0) && (fd_write_n (m->sd, m1->realm, n) < n)) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to write v1 message realm (%d bytes)", n));
        return (EMUNGE_SOCKET);
    }
    n = m1->data_len;
    if ((n > 0) && (fd_write_n (m->sd, m1->data, n) < n)) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to write v1 message data (%d bytes)", n));
        return (EMUNGE_SOCKET);
    }
    return (EMUNGE_SUCCESS);
}


munge_err_t
_munge_msg_recv (munge_msg_t m)
{
    int                  n;
    struct munge_msg_v1 *m1;

    assert (m != NULL);
    assert (m->sd >= 0);
    assert (m->pbody == NULL);

    n = sizeof (m->head);
    if (fd_read_n (m->sd, &(m->head), n) < n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to read message header (%d bytes)", n));
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
    n = m->head.length + 1;             /* reserve space for terminating NUL */
    if (!(m->pbody = malloc (n))) {
        _munge_msg_set_err (m, EMUNGE_NO_MEMORY,
            strdupf ("Unable to malloc %d bytes for message", n));
        return (EMUNGE_NO_MEMORY);
    }
    m->pbody_len = n;
    n = m->head.length;
    if (fd_read_n (m->sd, m->pbody, n) < n) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to read v1 message body (%d bytes)", n));
        return (EMUNGE_SOCKET);
    }
    m1 = m->pbody;
    n = sizeof (*m1);
    if (m1->realm_len > 0) {
        m1->realm = ((char *) m1) + n;  /* m1->realm is inside m->pbody mem */
        n += m1->realm_len;
    }
    else {
        m1->realm = NULL;
    }
    if (m1->data_len > 0) {
        m1->data = ((char *) m1) + n;   /* m1->data is inside m->pbody mem */
        n += m1->data_len;
    }
    else {
        m1->data = NULL;
    }
    assert (n == m->head.length);
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


char *
_munge_msg_get_err (munge_msg_t m)
{
    assert (m != NULL);

    return (m->errstr);
}


int
_munge_msg_set_err (munge_msg_t m, munge_err_t e, const char *str)
{
/*  Set an error code [e] and string [str] if an error condition
 *    does not already exist (ie, m->status == EMUNGE_SUCCESS).
 *  If [str] is not NULL, that string (and _not_ a copy) will be stored
 *    and later free()'d by the message destructor; if [str] is NULL,
 *    munge_strerror() will be used.  Thus, if multiple errors are set,
 *    only the first one is reported.
 *  Always returns -1.
 */
    assert (m != NULL);

    /*  Do nothing if an error does not exist or an error has already been set.
     */
    if ((e == EMUNGE_SUCCESS) || (m->status != EMUNGE_SUCCESS)) {
        if (str) {
            free (str);
        }
    }
    else {
        m->status = e;
        assert (m->errstr == NULL);
        m->errstr = (str != NULL) ? str : strdup (munge_strerror (e));;
    }
    /*  Screw you guys, I'm goin' home.
     */
    return (-1);
}
