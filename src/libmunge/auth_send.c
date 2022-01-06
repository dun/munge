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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <munge.h>
#include "m_msg.h"


/*****************************************************************************
 *  null client
 *****************************************************************************/

#if !defined(AUTH_METHOD_RECVFD_MKFIFO) && !defined(AUTH_METHOD_RECVFD_MKNOD)

int
auth_send (m_msg_t m)
{
    return (EMUNGE_SUCCESS);
}

#endif /* !AUTH_METHOD_RECVFD_MKFIFO && !AUTH_METHOD_RECVFD_MKNOD */


/*****************************************************************************
 *  strrecvfd struct (common)
 *****************************************************************************/

#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)

#include <assert.h>
#include <errno.h>
#include <fcntl.h>                      /* open, O_RDONLY, etc. */
#include <stdio.h>                      /* snprintf */
#include <stdlib.h>
#include <string.h>                     /* strdup, strerror, strrchr */
#include <stropts.h>                    /* I_SENDFD */
#include <sys/ioctl.h>                  /* ioctl */
#include <sys/stat.h>                   /* I_IRUSR */
#include <unistd.h>                     /* unlink, close */
#include "munge_defs.h"
#include "str.h"

static int _recv_auth_req (int sd, char **pipe_name_p, char **file_dir_p);
static int _name_auth_file (const char *pipe_name, const char *file_dir,
        char **file_name_p);

int
auth_send (m_msg_t m)
{
    char *pipe_name = NULL;
    char *file_dir = NULL;
    char *file_name = NULL;
    int   file_fd = -1;
    int   pipe_fd = -1;
    char *estr;

    if (_recv_auth_req (m->sd, &pipe_name, &file_dir) < 0) {
        estr = strdup ("Failed to receive auth request");
        goto err;
    }
    assert (pipe_name != NULL);
    if (_name_auth_file (pipe_name, file_dir, &file_name) < 0) {
        estr = strdup ("Failed to name auth file");
        goto err;
    }
    assert (file_name != NULL);
    unlink (file_name);                 /* in case it already exists */

    if ((file_fd= open (file_name, O_RDONLY | O_CREAT | O_EXCL, S_IRUSR)) <0) {
        estr = strdupf ("Failed to open auth file \"%s\": %s",
            file_name, strerror (errno));
        goto err;
    }
    if (unlink (file_name) < 0) {
        estr = strdupf ("Failed to remove auth file \"%s\": %s",
            file_name, strerror (errno));
        goto err;
    }
    if ((pipe_fd = open (pipe_name, O_WRONLY)) < 0) {
        estr = strdupf ("Failed to open auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (ioctl (pipe_fd, I_SENDFD, file_fd) < 0) {
        estr = strdupf ("Failed to send client identity: %s",
            strerror (errno));
        goto err;
    }
    if (close (pipe_fd) < 0) {
        estr = strdupf ("Failed to close auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (close (file_fd) < 0) {
        estr = strdupf ("Failed to close auth file \"%s\": %s",
            file_name, strerror (errno));
        goto err;
    }
    free (pipe_name);
    free (file_dir);
    free (file_name);
    return (0);

err:
    if (pipe_fd >= 0) {
        (void) close (pipe_fd);
    }
    if (pipe_name != NULL) {
        free (pipe_name);
    }
    if (file_fd >= 0) {
        (void) close (file_fd);
    }
    if (file_name != NULL) {
        (void) unlink (file_name);
        free (file_name);
    }
    if (file_dir != NULL) {
        free (file_dir);
    }
    return (m_msg_set_err (m, EMUNGE_SNAFU, estr));
}

static int
_recv_auth_req (int sd, char **pipe_name_p, char **file_dir_p)
{
/*  Receives an authentication request from the server on the established
 *    socket [sd], storing the path name of the authentication pipe to use for
 *    sending an fd across in a newly-allocated string referenced by
 *    [pipe_name_p], as well as the directory name in which to create the
 *    authentication file [file_dir_p] corresponding to the fd to be sent.
 *  The caller is responsible for freeing these strings.
 *  Returns 0 on success, -1 on error.
 */
    m_msg_t      m;
    munge_err_t  e;

    *pipe_name_p = NULL;
    *file_dir_p = NULL;

    if ((e = m_msg_create (&m)) != EMUNGE_SUCCESS) {
        goto end;
    }
    if ((e = m_msg_bind (m, sd)) != EMUNGE_SUCCESS) {
        goto end;
    }
    if ((e = m_msg_recv (m, MUNGE_MSG_AUTH_FD_REQ, 0)) != EMUNGE_SUCCESS) {
        goto end;
    }
    /*  Note that error_str will be set if the received message is an error
     *    message, whereas m_msg_recv()'s return code (e) will be set
     *    according to how that message is received.
     */
    if (m->error_str != NULL) {
        e = EMUNGE_SOCKET;
        goto end;
    }
    *pipe_name_p = m->auth_s_str;
    m->auth_s_is_copy = 1;
    *file_dir_p = m->auth_c_str;
    m->auth_c_is_copy = 1;

end:
    if (m) {
        m->sd = -1;                     /* prevent close by m_msg_destroy() */
        m_msg_destroy (m);
    }
    return (e == EMUNGE_SUCCESS ? 0 : -1);
}

static int
_name_auth_file (const char *pipe_name, const char *file_dir,
        char **file_name_p)
{
/*  Creates a unique filename based on the name of authentication pipe
 *    [pipe_name] and authentication file directory [file_dir], storing the
 *    result in a newly-allocated string referenced by [file_name_p].
 *  The caller is responsible for freeing the string returned by [file_name_p].
 *  The auth pipe name is of the form "AUTH_PIPE_DIR/.munge-RANDOM.pipe".
 *  The auth file name is of the form "AUTH_FILE_DIR/.munge-RANDOM.file".
 *  Returns 0 on success, -1 on error.
 *
 *  The random component of the authentication file is computed by XORing the
 *    first half of the random component of the authentication pipe with the
 *    second half.  Consequently, it is half the length.
 *  The random component of the client is based off that of the server because
 *    the client does not have access to the PRNG.  At the same time, we don't
 *    want to allow an attacker to derive the name of the authentication pipe
 *    from that of the authentication file (assuming the directory containing
 *    the authentication pipe is unreadable).
 */
    char *p;
    char *q;
    int   rnd_bin_len;
    char *rnd_bin = NULL;
    int   rnd_asc_len;
    char *rnd_asc = NULL;
    int   m;
    int   i;
    int   dst_len;
    char *dst = NULL;
    int   n;

    *file_name_p = NULL;

    if (!pipe_name || !file_dir) {
        goto err;
    }
    p = (p = strrchr (pipe_name, '-')) ? p + 1 : NULL;
    q = strrchr (pipe_name, '.');
    if (!p || !q) {
        goto err;
    }
    rnd_bin_len = (q - p) / 2;
    if (!(rnd_bin = malloc (rnd_bin_len))) {
        goto err;
    }
    rnd_asc_len = rnd_bin_len + 1;
    if (!(rnd_asc = malloc (rnd_asc_len))) {
        goto err;
    }
    if (!(strhex2bin (rnd_bin, rnd_bin_len, p, q - p))) {
        goto err;
    }
    m = rnd_bin_len / 2;
    for (i = 0; i < m; i++) {
        rnd_bin [i] ^= rnd_bin [i + m];
    }
    if (!(strbin2hex (rnd_asc, rnd_asc_len, rnd_bin, m))) {
        goto err;
    }
    dst_len = strlen (file_dir)
        + 8                             /* strlen ("/.munge-") */
        + strlen (rnd_asc)
        + 6;                            /* strlen (".file") + "\0" */
    if (!(dst = malloc (dst_len))) {
        goto err;
    }
    n = snprintf (dst, dst_len, "%s/.munge-%s.file", file_dir, rnd_asc);
    if ((n < 0) || (n >= dst_len)) {
        goto err;
    }
    free (rnd_bin);
    free (rnd_asc);
    *file_name_p = dst;
    return (0);

err:
    if (rnd_bin) {
        free (rnd_bin);
    }
    if (rnd_asc) {
        free (rnd_asc);
    }
    if (dst) {
        free (dst);
    }
    return (-1);
}

#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */
