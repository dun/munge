/*****************************************************************************
 *  $Id: auth_recv.c,v 1.4 2004/07/23 22:22:21 dun Exp $
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <munge.h>
#include "auth_policy.h"
#include "log.h"
#include "munge_msg.h"


/*****************************************************************************
 *  initialization
 *****************************************************************************/

void
auth_recv_init (void)
{
#ifdef MUNGE_AUTH_RECVFD_MKNOD
    if (geteuid() != 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The munge daemon requires root privileges");
    }
#endif /* MUNGE_AUTH_RECVFD_MKNOD */

    return;
}


/*****************************************************************************
 *  getpeereid
 *****************************************************************************/

#ifdef MUNGE_AUTH_GETPEEREID

int
auth_recv (munge_msg_t m, uid_t *uid, gid_t *gid)
{
    if (getpeereid (m->sd, uid, gid) < 0) {
        log_msg (LOG_ERR, "Unable to get peer identity: %s", strerror (errno));
        return (-1);
    }
    return (0);
}

#endif /* MUNGE_AUTH_GETPEEREID */


/*****************************************************************************
 *  peercred sockopt
 *****************************************************************************/

#ifdef MUNGE_AUTH_PEERCRED

#include <sys/socket.h>

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;                  /* socklen_t is uint32_t in Posix.1g */
#endif /* !HAVE_SOCKLEN_T */
                                                                                
int
auth_recv (munge_msg_t m, uid_t *uid, gid_t *gid)
{
    struct ucred cred;
    socklen_t len = sizeof (cred);

    if (getsockopt (m->sd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        log_msg (LOG_ERR, "Unable to get peer identity: %s", strerror (errno));
        return (-1);
    }
    *uid = cred.uid;
    *gid = cred.gid;
    return (0);
}

#endif /* MUNGE_AUTH_PEERCRED */


/*****************************************************************************
 *  strrecvfd struct (mkfifo)
 *****************************************************************************/

#ifdef MUNGE_AUTH_RECVFD_MKFIFO

#include <fcntl.h>                      /* open, O_RDONLY */
#include <sys/ioctl.h>                  /* ioctl */
#include <sys/stat.h>                   /* mkfifo, S_IWUSR, etc. */
#include <stropts.h>                    /* I_RECVFD, struct strrecvfd */

static int _name_auth_pipe (char *dst, int dstlen);
static int _send_auth_req (int sd, const char *pipe_name);

int
auth_recv (munge_msg_t m, uid_t *uid, gid_t *gid)
{
    char              pipe_name [AUTH_PIPE_NAME_MAX_LEN] = "";
    int               pipe_fd = -1;
    struct strrecvfd  recvfd;

    if (_name_auth_pipe (pipe_name, sizeof (pipe_name)) < 0) {
        log_msg (LOG_ERR, "Unable to name auth pipe");
        goto err;
    }
    unlink (pipe_name);                 /* in case it already exists */
    /*
     *  The auth pipe must be created in the filesystem before the auth req
     *    is sent to the client in order to prevent a race condition.
     */
    if (mkfifo (pipe_name, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH) < 0) {
        log_msg (LOG_ERR, "Unable to create auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (_send_auth_req (m->sd, pipe_name) < 0) {
        log_msg (LOG_ERR, "Unable to send auth request");
        goto err;
    }
    /*  This open() blocks until the client opens the fifo for writing.
     *
     *  FIXME: The open() & ioctl() calls could block and lead to a DoS attack.
     */
    if ((pipe_fd = open (pipe_name, O_RDONLY)) < 0) {
        log_msg (LOG_ERR, "Unable to open auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (ioctl (pipe_fd, I_RECVFD, &recvfd) < 0) {
        log_msg (LOG_ERR, "Unable to receive client identity: %s",
            strerror (errno));
        goto err;
    }
    /*  Authentication has succeeded at this point,
     *    so the following "errors" are not considered fatal.
     */
    if (close (recvfd.fd) < 0) {
        log_msg (LOG_WARNING, "Unable to close auth fd from \"%s\": %s",
            pipe_name, strerror (errno));
    }
    if (close (pipe_fd) < 0) {
        log_msg (LOG_WARNING, "Unable to close auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
    }
    if (unlink (pipe_name) < 0) {
        log_msg (LOG_WARNING, "Unable to remove auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
    }
    *uid = recvfd.uid;
    *gid = recvfd.gid;
    return (0);

err:
    if (pipe_fd >= 0)
        close (pipe_fd);
    if (pipe_name != NULL)
        unlink (pipe_name);
    return (-1);
}

#endif /* MUNGE_AUTH_RECVFD_MKFIFO */


/*****************************************************************************
 *  strrecvfd struct (mknod)
 *****************************************************************************/

#ifdef MUNGE_AUTH_RECVFD_MKNOD

#include <fcntl.h>                      /* open, O_RDWR */
#include <stropts.h>                    /* struct strrecvfd, I_RECVFD */
#include <sys/ioctl.h>                  /* ioctl */
#include <sys/stat.h>                   /* struct stat, mknod, S_IFCHR */
#include <sys/stream.h>                 /* queue_t */
#include <sys/uio.h>                    /* include before stream.h for aix */

static int _ns_pipe (const char *name, int fds[2]);
static int _s_pipe (int fd[2]);
static int _name_auth_pipe (char *dst, int dstlen);
static int _send_auth_req (int sd, const char *pipe_name);

int
auth_recv (munge_msg_t m, uid_t *uid, gid_t *gid)
{
    char              pipe_name [AUTH_PIPE_NAME_MAX_LEN] = "";
    int               pipe_fds[2] = {-1, -1};
    struct strrecvfd  recvfd;

    if (_name_auth_pipe (pipe_name, sizeof (pipe_name)) < 0) {
        log_msg (LOG_ERR, "Unable to name auth pipe");
        goto err;
    }
    /*  The auth pipe must be created in the filesystem before the auth req
     *    is sent to the client in order to prevent a race condition.
     */
    if ((_ns_pipe (pipe_name, pipe_fds)) < 0) {
        log_msg (LOG_ERR, "Unable to create auth pipe \"%s\"", pipe_name);
        goto err;
    }
    if (_send_auth_req (m->sd, pipe_name) < 0) {
        log_msg (LOG_ERR, "Unable to send auth request");
        goto err;
    }
    /*  FIXME: The ioctl() call could block and lead to a DoS attack.
     */
    if (ioctl (pipe_fds[0], I_RECVFD, &recvfd) < 0) {
        log_msg (LOG_ERR, "Unable to receive client identity: %s",
            strerror (errno));
        goto err;
    }
    /*  Authentication has succeeded at this point,
     *    so the following "errors" are not considered fatal.
     */
    if (close (recvfd.fd) < 0) {
        log_msg (LOG_WARNING, "Unable to close auth fd from \"%s\": %s",
            pipe_name, strerror (errno));
    }
    if (close (pipe_fds[0]) < 0) {
        log_msg (LOG_WARNING,
            "Unable to close auth pipe \"%s\" for reading: %s",
            pipe_name, strerror (errno));
    }
    if (close (pipe_fds[1]) < 0) {
        log_msg (LOG_WARNING,
            "Unable to close auth pipe \"%s\" for writing: %s",
            pipe_name, strerror (errno));
    }
    if (unlink (pipe_name) < 0) {
        log_msg (LOG_WARNING, "Unable to remove auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
    }
    *uid = recvfd.uid;
    *gid = recvfd.gid;
    return (0);

err:
    if (pipe_fds[0] >= 0)
        close (pipe_fds[0]);
    if (pipe_fds[1] >= 0)
        close (pipe_fds[1]);
    if (pipe_name != NULL)
        unlink (pipe_name);
    return (-1);
}

static int
_ns_pipe (const char *name, int fd[2])
{
/*  Creates a named stream pipe for SVR3 (cf, Stevens UNP1e, section 7.9).
 *    To create a named stream pipe, we have to call mknod().  While any
 *    user can call it to create a FIFO, only root can call it for any other
 *    purpose.  Consequently, root privileges are required to create a named
 *    stream pipe.
 *  The "write" end (ie, fd[1]) of this named stream pipe will be bound to
 *    [name] since the client will open it by name in order to write its fd.
 *  Returns 0 on success, -1 on error.
 */
    int omask;
    struct stat stbuf;

    /*  Start with creating an unnamed stream pipe.
     */
    if (_s_pipe (fd) < 0) {
        return (-1);
    }
    /*  Ensure mode is 0666, notb.
     */
    omask = umask (0);
    /*
     *  Unlink this name in case it already exists.
     */
    unlink (name);
    /*
     *  Determine the major/minor device numbers of one end of the pipe.
     */
    if (fstat (fd[1], &stbuf) < 0) {
        close (fd[0]);
        close (fd[1]);
        return (-1);
    }
    /*  Create the filesystem entry by assigning the [name] to one end
     *    of the pipe.  This requires root privileges.
     */
    if (mknod (name, S_IFCHR | 0666, stbuf.st_rdev) < 0) {
        close (fd[0]);
        close (fd[1]);
        umask (omask);
        return (-1);
    }
    umask (omask);
    return (0);
}

static int
_s_pipe (int fd[2])
{
/*  Creates an unnamed stream pipe for SVR3 (cf, Stevens UNP1e, section 7.9).
 *  Returns 0 on success, -1 on error.
 */
    struct strfdinsert ins;
    queue_t *pointer;

    /*  Open the stream clone device "/dev/spx" twice.
     */
    if ((fd[0] = open ("/dev/spx", O_RDWR)) < 0) {
        return (-1);
    }
    if ((fd[1] = open ("/dev/spx", O_RDWR)) < 0) {
        close (fd[0]);
        return (-1);
    }
    /*  Link these two streams together with an I_FDINSERT ioctl.
     */
    ins.ctlbuf.buf = (char *) &pointer; /* no ctrl info, just the ptr */
    ins.ctlbuf.len = sizeof (queue_t *);
    ins.ctlbuf.maxlen = sizeof (queue_t *);

    ins.databuf.buf = (char *) 0;       /* no data to send */
    ins.databuf.len = -1;               /* magic: must be -1 for stream pipe */
    ins.databuf.maxlen = 0;

    ins.fildes = fd[1];                 /* the fd to connect with fd[0] */
    ins.flags = 0;                      /* non-priority message */
    ins.offset = 0;                     /* offset of pointer in ctlbuf */

    if (ioctl (fd[0], I_FDINSERT, (char *) &ins) < 0) {
        close (fd[0]);
        close (fd[1]);
        return (-1);
    }
    return (0);
}

#endif /* MUNGE_AUTH_RECVFD_MKNOD */


/*****************************************************************************
 *  strrecvfd struct (common)
 *****************************************************************************/

#ifdef MUNGE_AUTH_RECVFD_COMMON

#include <stdio.h>                      /* snprintf */
#include <stdlib.h>                     /* malloc */
#include <string.h>                     /* memset, strlen */
#include "random.h"                     /* random_pseudo_bytes */
#include "str.h"                        /* strhex */

static int
_name_auth_pipe (char *dst, int dstlen)
{
/*  Creates a unique filename for the authentication pipe,
 *    storing the result in buffer [dst] of length [dstlen].
 *  Returns 0 on success, -1 on error.
 */
    unsigned char  nonce_bin [AUTH_PIPE_NAME_RND_BYTES];
    char           nonce_str [(sizeof (nonce_bin) * 2) + 1];
    char          *p;
    int            n;

    random_pseudo_bytes (nonce_bin, sizeof (nonce_bin));

    p = strhex (nonce_str, sizeof (nonce_str), nonce_bin, sizeof (nonce_bin));
    if (p == NULL) {
        return (-1);
    }
    n = snprintf (dst, dstlen, "%s/.munge-%s.pipe",
        AUTH_PIPE_NAME_PREFIX, nonce_str);
    if ((n < 0) || (n >= dstlen)) {
        return (-1);
    }
    return (0);
}

static int
_send_auth_req (int sd, const char *pipe_name)
{
/*  Sends an authentication request to the client on the established
 *    socket [sd] using [pipe_name] as the authentication pipe to use
 *    for sending an fd across.
 *  Returns 0 on success, -1 on error.
 *
 *  The authentication request message needs to contain the name of the
 *    authentication pipe for the client to use for sending an fd across.
 *
 *  FIXME: Use of the munge_msg_v1 struct is overkill here, but all of the
 *         existing msg routines currently expect to work with that struct.
 */
    munge_msg_t          m;
    munge_err_t          e;
    struct munge_msg_v1 *m1;

    if ((e = _munge_msg_create (&m, sd)) != EMUNGE_SUCCESS) {
        goto end;
    }
    m->head.type = MUNGE_MSG_AUTH_FD_REQ;

    m->pbody_len = sizeof (struct munge_msg_v1);
    if (!(m->pbody = malloc (m->pbody_len))) {
        e = EMUNGE_NO_MEMORY;
        goto end;
    }
    memset (m->pbody, 0, m->pbody_len);
    m1 = m->pbody;
    /*
     *  Note that the actual string reference (not a copy) is used here
     *    since _munge_msg_destroy() does not free any m1 fields.
     */
    m1->data_len = strlen ((char *) pipe_name) + 1;
    m1->data = (char *) pipe_name;

    if ((e = _munge_msg_send (m)) != EMUNGE_SUCCESS) {
        goto end;
    }

end:
    /*  Clear the msg sd to prevent closing the socket by _munge_msg_destroy().
     */
    if (m) {
        m->sd = -1;
        _munge_msg_destroy (m);
    }
    return (e == EMUNGE_SUCCESS ? 0 : -1);
}

#endif /* MUNGE_AUTH_RECVFD_COMMON */
