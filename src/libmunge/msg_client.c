/*****************************************************************************
 *  $Id: msg_client.c,v 1.1 2003/04/08 18:16:16 dun Exp $
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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <munge.h>
#include "ctx.h"
#include "dprintf.h"
#include "msg_client.h"
#include "strlcpy.h"


munge_err_t
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
    if ((sd = socket (PF_LOCAL, SOCK_STREAM, 0)) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to create socket: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_LOCAL;
    n = strlcpy (addr.sun_path, path, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        close (sd);
        _munge_msg_set_err (m, EMUNGE_OVERFLOW,
            strdup ("Exceeded maximum length of socket pathname"));
        return (EMUNGE_OVERFLOW);
    }
    i = 1;
    delay = 1;
    for (;;) {
        /*
         * If a call to connect() for a Unix domain stream socket finds that
         *   the listening socket's queue is full, ECONNREFUSED is returned
         *   immediately.  (cf, Stevens UNPv1, s14.4, p378)
         * In case of ECONNREFUSED, try again up to MUNGE_SOCKET_RETRIES.
         */
        DPRINTF ((10, "Connecting to \"%s\" (#%d) ...\n", path, i));
        n = connect (sd, (struct sockaddr *) &addr, sizeof (addr));
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        if (errno != ECONNREFUSED)
            break;
        if (i >= MUNGE_SOCKET_RETRIES)
            break;
        sleep (delay);
        delay *= 2;                     /* exponential backoff */
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


munge_err_t
_munge_msg_client_disconnect (munge_msg_t m)
{
    munge_err_t e = EMUNGE_SUCCESS;

    assert (m != NULL);
    assert (m->sd >= 0);

    if (m->sd >= 0) {
        if (close (m->sd) < 0) {
            _munge_msg_set_err (m, EMUNGE_SOCKET,
                strdupf ("Unable to close socket: %s", strerror (errno)));
            e = EMUNGE_SOCKET;
        }
        m->sd = -1;
    }
    return (e);
}


munge_err_t
_munge_msg_client_enc_req_v1 (munge_msg_t m, munge_ctx_t ctx,
                              const void *buf, int len)
{
    struct munge_msg_v1 *m1;

    assert (m != NULL);
    assert (m->head.version == 1);
    assert (m->pbody == NULL);

    if (!(m->pbody = malloc (sizeof (struct munge_msg_v1))))
        return (EMUNGE_NO_MEMORY);
    memset (m->pbody, 0, sizeof (struct munge_msg_v1));
    m->pbody_len = sizeof (struct munge_msg_v1);
    m1 = m->pbody;

    if (ctx) {
        m1->cipher = ctx->cipher;
        m1->zip = ctx->zip;
        m1->mac = ctx->mac;
        if (ctx->realm) {
            m1->realm_len = strlen (ctx->realm) + 1;
            m1->realm = ctx->realm;
        }
        else {
            m1->realm_len = 0;
            m1->realm = NULL;
        }
        m1->ttl = ctx->ttl;
    }
    else {
        m1->cipher = MUNGE_CIPHER_DEFAULT;
        m1->zip = MUNGE_ZIP_DEFAULT;
        m1->mac = MUNGE_MAC_DEFAULT;
        m1->realm_len = 0;
        m1->realm = NULL;
        m1->ttl = 0;
    }
    m1->data_len = len;
    m1->data = buf;
    return (EMUNGE_SUCCESS);
}


munge_err_t
_munge_msg_client_enc_rsp_v1 (munge_msg_t m, char **cred)
{
    struct munge_msg_v1 *m1;
    char *p;

    assert (m != NULL);
    assert (m->head.version == 1);
    assert (cred != NULL);

    m1 = (struct munge_msg_v1 *) m->pbody;

    if (m1->data_len <= 0) {
        return (EMUNGE_SNAFU);
    }
    if (!(p = malloc (m1->data_len + 1))) { /* reserved for terminating NUL */
        return (EMUNGE_NO_MEMORY);
    }
    memcpy (p, m1->data, m1->data_len);
    p[m1->data_len] = '\0';
    *cred = p;
    return (EMUNGE_SUCCESS);
}


munge_err_t
_munge_msg_client_dec_req_v1 (munge_msg_t m)
{
    return (EMUNGE_SNAFU);
}


munge_err_t
_munge_msg_client_dec_rsp_v1 (munge_msg_t m)
{
    return (EMUNGE_SNAFU);
}
