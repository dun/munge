/*****************************************************************************
 *  $Id: msg_client.c,v 1.10 2004/09/23 20:56:43 dun Exp $
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
#include <string.h>
#include <sys/types.h>                  /* include before socket.h for bsd */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <munge.h>
#include "auth_send.h"
#include "ctx.h"
#include "msg_client.h"
#include "munge_defs.h"
#include "munge_msg.h"
#include "str.h"
#include "strlcpy.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static munge_err_t _munge_msg_client_connect (munge_msg_t m, char *path);
static munge_err_t _munge_msg_client_disconnect (munge_msg_t m);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
munge_msg_client_xfer (munge_msg_t *pm, munge_ctx_t ctx)
{
    char        *socket;
    int          i;
    munge_err_t  e;
    munge_msg_t  mreq, mrsp;

    if (!pm || !*pm) {
        return (EMUNGE_SNAFU);
    }
    if (!ctx || !(socket = ctx->socket)) {
        socket = MUNGE_SOCKET_NAME;
    }
    mreq = *pm;
    mrsp = NULL;
    i = 1;
    while (1) {
        if ((e = _munge_msg_client_connect (mreq, socket)) != EMUNGE_SUCCESS) {
            break;
        }
        else if ((e = _munge_msg_send (mreq)) != EMUNGE_SUCCESS) {
            ; /* empty */
        }
        else if (auth_send (mreq) < 0) {
            e = EMUNGE_SOCKET;
        }
        else if ((e = _munge_msg_create (&mrsp, mreq->sd)) != EMUNGE_SUCCESS) {
            break;
        }
        else if ((e = _munge_msg_recv (mrsp)) != EMUNGE_SUCCESS) {
            ; /* empty */
        }
        else if ((e = _munge_msg_client_disconnect (mrsp)) != EMUNGE_SUCCESS) {
            break;
        }
        else if (e == EMUNGE_SUCCESS) {
            break;
        }

        if (i >= MUNGE_SOCKET_XFER_ATTEMPTS) {
            break;
        }
        if (mrsp != NULL) {
            mrsp->sd = -1;              /* prevent socket close by destroy() */
            _munge_msg_destroy (mrsp);
            mrsp = NULL;
        }
        if (mreq->sd >= 0) {
            (void) close (mreq->sd);
            mreq->sd = -1;
        }
        mreq->head.retry = i;
        i++;
    }
    if (mrsp) {
        *pm = mrsp;
        mreq->sd = -1;                  /* prevent socket close by destroy() */
        _munge_msg_destroy (mreq);
    }
    return (e);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static munge_err_t
_munge_msg_client_connect (munge_msg_t m, char *path)
{
    struct stat         st;
    struct sockaddr_un  addr;
    int                 sd;
    int                 n;
    int                 i;
    int                 delay;

    assert (m != NULL);
    assert (m->sd < 0);

    if ((path == NULL) || (*path == '\0')) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Munge socket has no name"));
        return (EMUNGE_SOCKET);
    }
    if (stat (path, &st) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to access \"%s\": %s", path, strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (!S_ISSOCK (st.st_mode)) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Invalid file type for socket \"%s\"", path));
        return (EMUNGE_SOCKET);
    }
    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to create socket: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, path, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        close (sd);
        _munge_msg_set_err (m, EMUNGE_OVERFLOW,
            strdup ("Exceeded maximum length of socket pathname"));
        return (EMUNGE_OVERFLOW);
    }
    i = 1;
    delay = 1;
    while (1) {
        /*
         * If a call to connect() for a Unix domain stream socket finds that
         *   the listening socket's queue is full, ECONNREFUSED is returned
         *   immediately.  (cf, Stevens UNPv1, s14.4, p378)
         * If ECONNREFUSED, try again up to MUNGE_SOCKET_CONNECT_ATTEMPTS.
         */
        n = connect (sd, (struct sockaddr *) &addr, sizeof (addr));

        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != ECONNREFUSED) {
            break;
        }
        if (i >= MUNGE_SOCKET_CONNECT_ATTEMPTS) {
            break;
        }
        sleep (delay);
        delay++;
        i++;
    }
    if (n < 0) {
        close (sd);
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to connect to \"%s\": %s", path,
            strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    m->sd = sd;
    return (EMUNGE_SUCCESS);
}


static munge_err_t
_munge_msg_client_disconnect (munge_msg_t m) {
    munge_err_t e;

    assert (m != NULL);
    assert (m->sd >= 0);

    if (close (m->sd) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to close socket: %s", strerror (errno)));
        e = EMUNGE_SOCKET;
    }
    else {
        e = EMUNGE_SUCCESS;
    }
    m->sd = -1;
    return (e);
}
