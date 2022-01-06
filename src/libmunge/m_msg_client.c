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
#include <string.h>
#include <sys/types.h>                  /* include before socket.h for bsd */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>
#include "auth_send.h"
#include "ctx.h"
#include "fd.h"
#include "m_msg.h"
#include "m_msg_client.h"
#include "munge_defs.h"
#include "str.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static munge_err_t _m_msg_client_connect (m_msg_t m, char *path);
static munge_err_t _m_msg_client_disconnect (m_msg_t m);
static munge_err_t _m_msg_client_millisleep (m_msg_t m, unsigned long msecs);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
m_msg_client_xfer (m_msg_t *pm, m_msg_type_t mreq_type, munge_ctx_t ctx)
{
    char         *socket;
    int           i;
    munge_err_t   e;
    m_msg_t       mreq, mrsp;
    m_msg_type_t  mrsp_type;

    if (!pm || !*pm) {
        return (EMUNGE_SNAFU);
    }
    if (!ctx || !(socket = ctx->socket_str)) {
        socket = MUNGE_SOCKET_NAME;
    }
    mreq = *pm;
    mrsp = NULL;
    if (mreq_type == MUNGE_MSG_ENC_REQ) {
        mrsp_type = MUNGE_MSG_ENC_RSP;
    }
    else if (mreq_type == MUNGE_MSG_DEC_REQ) {
        mrsp_type = MUNGE_MSG_DEC_RSP;
    }
    else {
        return (EMUNGE_SNAFU);
    }

    i = 1;
    while (1) {
        if ((e = _m_msg_client_connect (mreq, socket)) != EMUNGE_SUCCESS) {
            break;
        }
        else if ((e = m_msg_send (mreq, mreq_type, MUNGE_MAXIMUM_REQ_LEN))
                != EMUNGE_SUCCESS) {
            ; /* empty */
        }
        else if (auth_send (mreq) < 0) {
            e = EMUNGE_SOCKET;
        }
        else if ((e = m_msg_create (&mrsp)) != EMUNGE_SUCCESS) {
            break;
        }
        else if ((e = m_msg_bind (mrsp, mreq->sd)) != EMUNGE_SUCCESS) {
            break;
        }
        else if ((e = m_msg_recv (mrsp, mrsp_type, 0)) != EMUNGE_SUCCESS) {
            ; /* empty */
        }
        else if ((e = _m_msg_client_disconnect (mrsp)) != EMUNGE_SUCCESS) {
            break;
        }
        else if (e == EMUNGE_SUCCESS) {
            break;
        }

        if (i >= MUNGE_SOCKET_RETRY_ATTEMPTS) {
            break;
        }
        if (e == EMUNGE_BAD_LENGTH) {
            break;
        }
        if (mrsp != NULL) {
            mrsp->sd = -1;              /* prevent socket close by destroy() */
            m_msg_destroy (mrsp);
            mrsp = NULL;
        }
        if (mreq->sd >= 0) {
            (void) close (mreq->sd);
            mreq->sd = -1;
        }
        mreq->retry = i;
        e = _m_msg_client_millisleep (mreq, i * MUNGE_SOCKET_RETRY_MSECS);
        if (e != EMUNGE_SUCCESS) {
            break;
        }
        i++;
    }
    if (mrsp) {
        *pm = mrsp;
        mreq->sd = -1;                  /* prevent socket close by destroy() */
        m_msg_destroy (mreq);
    }
    return (e);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static munge_err_t
_m_msg_client_connect (m_msg_t m, char *path)
{
    struct stat         st;
    struct sockaddr_un  addr;
    int                 sd;
    int                 n;
    int                 i;
    unsigned long       delay_msecs;

    assert (m != NULL);
    assert (m->sd < 0);

    if ((path == NULL) || (*path == '\0')) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("MUNGE socket name is undefined"));
        return (EMUNGE_SOCKET);
    }
    if (stat (path, &st) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to access \"%s\": %s (%s)",
            path, strerror (errno), "Did you start munged?"));
        return (EMUNGE_SOCKET);
    }
    if (!S_ISSOCK (st.st_mode)) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Invalid file type for socket \"%s\"", path));
        return (EMUNGE_SOCKET);
    }
    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to create socket: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (fd_set_nonblocking (sd) < 0) {
        close (sd);
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to set nonblocking socket: %s",
            strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[ sizeof (addr.sun_path) - 1 ] = '\0';
    strncpy (addr.sun_path, path, sizeof (addr.sun_path));
    if (addr.sun_path[ sizeof (addr.sun_path) - 1 ] != '\0') {
        close (sd);
        m_msg_set_err (m, EMUNGE_OVERFLOW,
            strdupf ("Exceeded maximum length of %lu bytes "
            "for socket pathname", sizeof (addr.sun_path)));
        return (EMUNGE_OVERFLOW);
    }
    i = 1;
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
        delay_msecs = i * MUNGE_SOCKET_CONNECT_RETRY_MSECS;
        if (_m_msg_client_millisleep (m, delay_msecs) != EMUNGE_SUCCESS) {
            break;
        }
        i++;
    }
    if (n < 0) {
        close (sd);
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to connect to \"%s\": %s", path,
            strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    m->sd = sd;
    return (EMUNGE_SUCCESS);
}


static munge_err_t
_m_msg_client_disconnect (m_msg_t m) {
    munge_err_t e;

    assert (m != NULL);
    assert (m->sd >= 0);

    if (close (m->sd) < 0) {
        m_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Failed to close socket: %s", strerror (errno)));
        e = EMUNGE_SOCKET;
    }
    else {
        e = EMUNGE_SUCCESS;
    }
    m->sd = -1;
    return (e);
}


static munge_err_t
_m_msg_client_millisleep (m_msg_t m, unsigned long msecs)
{
/*  Sleeps for 'msecs' milliseconds.
 *  Returns EMUNGE_SUCCESS on success,
 *    or EMUNGE_SNAFU on error (with additional info if 'm' is not NULL).
 */
    struct timespec ts;
    int rv;

    ts.tv_sec = msecs / 1000;
    ts.tv_nsec = (msecs % 1000) * 1000 * 1000;

    while (1) {
        rv = nanosleep (&ts, &ts);
        if (rv == 0) {
            break;
        }
        else if (errno == EINTR) {
            continue;
        }
        else if (m != NULL) {
            m_msg_set_err (m, EMUNGE_SNAFU,
                strdupf ("Failed nanosleep: %s", strerror (errno)));
        }
        return (EMUNGE_SNAFU);
    }
    return (EMUNGE_SUCCESS);
}
