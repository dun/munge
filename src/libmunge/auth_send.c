/*****************************************************************************
 *  $Id: auth_send.c,v 1.7 2004/11/24 00:21:57 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2004 The Regents of the University of California.
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <munge.h>
#include "auth_policy.h"
#include "msg.h"


/*****************************************************************************
 *  null client
 *****************************************************************************/

#ifndef MUNGE_AUTH_RECVFD_COMMON

int
auth_send (msg_t m)
{
    return (EMUNGE_SUCCESS);
}

#endif /* !MUNGE_AUTH_RECVFD_COMMON */


/*****************************************************************************
 *  strrecvfd struct (common)
 *****************************************************************************/

#ifdef MUNGE_AUTH_RECVFD_COMMON

#include <assert.h>
#include <errno.h>
#include <fcntl.h>                      /* open, O_RDONLY, etc. */
#include <stdlib.h>
#include <string.h>                     /* strdup, strerror, strrchr */
#include <stropts.h>                    /* I_SENDFD */
#include <sys/ioctl.h>                  /* ioctl */
#include <sys/stat.h>                   /* I_IRUSR */
#include <unistd.h>                     /* unlink, close */
#include "missing.h"
#include "munge_defs.h"
#include "str.h"

static int _recv_auth_req (int sd, char **dst_p);
static int _name_auth_file (const char *src, char **dst_p);

int
auth_send (msg_t m)
{
    char *pipe_name = NULL;
    int   pipe_fd = -1;
    char *file_name = NULL;
    int   file_fd = -1;
    char *estr;

    if (_recv_auth_req (m->sd, &pipe_name) < 0) {
        estr = strdup ("Unable to receive auth request");
        goto err;
    }
    assert (pipe_name != NULL);
    if (_name_auth_file (pipe_name, &file_name) < 0) {
        estr = strdup ("Unable to name auth file");
        goto err;
    }
    assert (file_name != NULL);
    unlink (file_name);                 /* in case it already exists */

    if ((file_fd= open (file_name, O_RDONLY | O_CREAT | O_EXCL, S_IRUSR)) <0) {
        estr = strdupf ("Unable to open auth file \"%s\": %s",
            file_name, strerror (errno));
        goto err;
    }
    if (unlink (file_name) < 0) {
        estr = strdupf ("Unable to remove auth file \"%s\": %s",
            file_name, strerror (errno));
        goto err;
    }
    if ((pipe_fd = open (pipe_name, O_WRONLY)) < 0) {
        estr = strdupf ("Unable to open auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (ioctl (pipe_fd, I_SENDFD, file_fd) < 0) {
        estr = strdupf ("Unable to send client identity: %s",
            strerror (errno));
        goto err;
    }
    if (close (pipe_fd) < 0) {
        estr = strdupf ("Unable to close auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (close (file_fd) < 0) {
        estr = strdupf ("Unable to close auth file \"%s\": %s",
            file_name, strerror (errno));
        goto err;
    }
    free (pipe_name);
    free (file_name);
    return (0);

err:
    if (pipe_fd >= 0) {
        close (pipe_fd);
    }
    if (pipe_name != NULL) {
        free (pipe_name);
    }
    if (file_fd >= 0) {
        close (file_fd);
    }
    if (file_name != NULL) {
        unlink (file_name);
        free (file_name);
    }
    return (msg_set_err (m, EMUNGE_SNAFU, estr));
}

static int
_recv_auth_req (int sd, char **dst_p)
{
/*  Receives an authentication request from the server on the established
 *    socket [sd], storing the name of the authentication pipe to use for
 *    sending an fd across in a newly-allocated string referenced by [dst_p].
 *  The caller is responsible for freeing the string returned by [dst_p].
 *  Returns 0 on success, -1 on error.
 */
    msg_t          m;
    munge_err_t    e;
    struct msg_v1 *m1;

    *dst_p = NULL;

    if ((e = msg_create (&m, sd)) != EMUNGE_SUCCESS) {
        goto end;
    }
    if ((e = msg_recv (m, 0)) != EMUNGE_SUCCESS) {
        goto end;
    }
    /*  Note that errstr will be set if the received message is an error
     *    message, whereas msg_recv()'s return code (e) will be set
     *    according to how that message is received.
     */
    if (m->errstr != NULL) {
        e = EMUNGE_SOCKET;
        goto end;
    }
    if (m->head.version > MUNGE_MSG_VERSION) {
        e = EMUNGE_SOCKET;
        goto end;
    }
    if (m->head.type != MUNGE_MSG_AUTH_FD_REQ) {
        e = EMUNGE_SOCKET;
        goto end;
    }
    m1 = m->pbody;
    /*
     *  The string must be copied since msg_destroy() will free the
     *    msg body, and the msg data here resides within that memory.
     */
    if (!(*dst_p = strdup (m1->data))) {
        e = EMUNGE_NO_MEMORY;
        goto end;
    }

end:
    /*  Clear the msg sd to prevent closing the socket by msg_destroy().
     */
    if (m) {
        m->sd = -1;
        msg_destroy (m);
    }
    return (e == EMUNGE_SUCCESS ? 0 : -1);
}

static int
_name_auth_file (const char *src, char **dst_p)
{
/*  Creates a unique filename based on the name of authentication pipe [src],
 *    storing the result in a newly-allocated string referenced by [dst_p].
 *  The caller is responsible for freeing the string returned by [dst_p].
 *  Returns 0 on success, -1 on error.
 */
    char *dst = NULL;
    int   dst_len;
    char *p;

    *dst_p = NULL;

    if (!(dst = strdup (src))) {
        goto err;
    }
    dst_len = strlen (dst) + 1;

    if (!(p = strrchr (dst, '.'))) {
        goto err;
    }
    *p = '\0';
    if (strlcat (dst, ".file", dst_len) >= dst_len) {
        goto err;
    }
    *dst_p = dst;
    return (0);

err:
    if (dst) {
        free (dst);
    }
    return (-1);
}

#endif /* MUNGE_AUTH_RECVFD_COMMON */
