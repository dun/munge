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

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <munge.h>
#include "log.h"
#include "m_msg.h"
#include "path.h"


/*****************************************************************************
 *  initialization
 *****************************************************************************/

static void _check_auth_server_dir (const char *dir, int got_force);
static void _check_auth_client_dir (const char *dir, int got_force);

void
auth_recv_init (const char *srvrdir, const char *clntdir, int got_force)
{
#ifdef AUTH_METHOD_RECVFD_MKNOD
    if (geteuid () != 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Root privileges are required for munged");
    }
#endif /* AUTH_METHOD_RECVFD_MKNOD */

    _check_auth_server_dir (srvrdir, got_force);
    _check_auth_client_dir (clntdir, got_force);

    return;
}

static void
_check_auth_server_dir (const char *dir, int got_force)
{
#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
    int          is_symlink;
    struct stat  st;
    int          n;
    char         ebuf [1024];

    if ((dir == NULL) || (*dir == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth server dir name is undefined");
    }
    is_symlink = (lstat (dir, &st) == 0) ? S_ISLNK (st.st_mode) : 0;

    if (stat (dir, &st) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to stat auth server dir \"%s\"", dir);
    }
    /*  Check if [dir] is an actual directory.
     */
    if (!S_ISDIR (st.st_mode)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth server dir is insecure: \"%s\" must be a directory",
            dir);
    }
    if (is_symlink) {
        log_err_or_warn (got_force,
            "The auth server dir is insecure: "
            "\"%s\" should not be a symbolic link", dir);
    }
    /*  Check if [dir] has valid ownership and permissions.
     */
    if (st.st_uid != geteuid ()) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth server dir is insecure: "
            "\"%s\" must be owned by UID %u", dir, (unsigned) geteuid ());
    }
    if (!(st.st_mode & S_IWUSR)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth server dir is insecure: "
            "\"%s\" must be writable by user", dir);
    }
    if (st.st_mode & S_IRGRP) {
        log_err_or_warn (got_force,
            "The auth server dir is insecure: "
            "\"%s\" should not be readable by group", dir);
    }
    if (st.st_mode & S_IROTH) {
        log_err_or_warn (got_force,
            "The auth server dir is insecure: "
            "\"%s\" should not be readable by other", dir);
    }
    /*  Check if [dir] is secure against modification by others.
     */
    n = path_is_secure (dir, ebuf, sizeof (ebuf), PATH_SECURITY_NO_FLAGS);
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check auth server dir \"%s\": %s", dir, ebuf);
    }
    else if (n == 0) {
        log_err_or_warn (got_force,
            "The auth server dir is insecure: %s", ebuf);
    }
    /*  Check if [dir] path is accessible by all.
     */
    n = path_is_accessible (dir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check auth server dir \"%s\": %s", dir, ebuf);
    }
    else if (n == 0) {
        log_err_or_warn (got_force,
            "The auth server dir is inaccessible: %s", ebuf);
    }
#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */
    return;
}

static void
_check_auth_client_dir (const char *dir, int got_force)
{
#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
    int          is_symlink;
    struct stat  st;
    int          n;
    char         parent_dir [PATH_MAX];
    char         ebuf [1024];

    if ((dir == NULL) || (*dir == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth client dir name is undefined");
    }
    is_symlink = (lstat (dir, &st) == 0) ? S_ISLNK (st.st_mode) : 0;

    if (stat (dir, &st) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check auth client dir \"%s\"", dir);
    }
    /*  Check if [dir] is an actual directory.
     */
    if (!S_ISDIR (st.st_mode)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth client dir is insecure: \"%s\" must be a directory",
            dir);
    }
    if (is_symlink) {
        log_err_or_warn (got_force,
            "The auth client dir is insecure: "
            "\"%s\" should not be a symbolic link", dir);
    }
    /*  Check if [dir] has valid ownership and permissions.
     */
    if ((st.st_uid != 0) && (st.st_uid != geteuid ())) {
        log_err_or_warn (got_force,
            "The auth client dir is insecure: "
            "\"%s\" should be owned by UID %u or UID 0",
            dir, (unsigned) geteuid ());
    }
    if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH | S_ISVTX))
            != (S_IWUSR | S_IWGRP | S_IWOTH | S_ISVTX)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "The auth client dir is insecure: "
            "\"%s\" must be writable by all with the sticky bit set", dir);
    }
    /*  Check if parent dir is secure against modification by others.
     */
    if (path_dirname (dir, parent_dir, sizeof (parent_dir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of auth client dir \"%s\"", dir);
    }
    n = path_is_secure (parent_dir, ebuf, sizeof (ebuf),
            PATH_SECURITY_NO_FLAGS);
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check auth client parent dir \"%s\": %s",
            parent_dir, ebuf);
    }
    else if (n == 0) {
        log_err_or_warn (got_force,
            "The auth client dir is insecure: %s", ebuf);
    }
    /*  Check if [dir] path is accessible by all.
     */
    n = path_is_accessible (dir, ebuf, sizeof (ebuf));
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check auth client dir \"%s\": %s", dir, ebuf);
    }
    else if (n == 0) {
        log_err_or_warn (got_force,
            "The auth client dir is inaccessible: %s", ebuf);
    }
#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */
    return;
}


/*****************************************************************************
 *  getpeereid
 *****************************************************************************/

#ifdef AUTH_METHOD_GETPEEREID

#include <sys/socket.h>
#include <sys/types.h>

int
auth_recv (m_msg_t m, uid_t *uid, gid_t *gid)
{
    if (getpeereid (m->sd, uid, gid) < 0) {
        log_msg (LOG_ERR, "Failed to get peer identity: %s", strerror (errno));
        return (-1);
    }
    return (0);
}

#endif /* AUTH_METHOD_GETPEEREID */


/*****************************************************************************
 *  getpeerucred
 *****************************************************************************/

#ifdef AUTH_METHOD_GETPEERUCRED

#include <ucred.h>

int
auth_recv (m_msg_t m, uid_t *uid, gid_t *gid)
{
    ucred_t *ucred = NULL;
    uid_t    uid_tmp;
    gid_t    gid_tmp;
    int      rc = -1;

    if (getpeerucred (m->sd, &ucred) < 0) {
        log_msg (LOG_ERR, "Failed to get peer ucred: %s", strerror (errno));
    }
    else if ((uid_tmp = ucred_geteuid (ucred)) < 0) {
        log_msg (LOG_ERR, "Failed to get peer UID: %s", strerror (errno));
    }
    else if ((gid_tmp = ucred_getegid (ucred)) < 0) {
        log_msg (LOG_ERR, "Failed to get peer GID: %s", strerror (errno));
    }
    else {
        *uid = uid_tmp;
        *gid = gid_tmp;
        rc = 0;
    }

    if (ucred) {
        ucred_free (ucred);
    }
    return (rc);
}

#endif /* AUTH_METHOD_GETPEERUCRED */


/*****************************************************************************
 *  SO_PEERCRED sockopt
 *****************************************************************************/

#ifdef AUTH_METHOD_SO_PEERCRED

#include <sys/socket.h>

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;                  /* socklen_t is uint32_t in Posix.1g */
#endif /* !HAVE_SOCKLEN_T */

int
auth_recv (m_msg_t m, uid_t *uid, gid_t *gid)
{
    struct ucred cred;
    socklen_t len = sizeof (cred);

    if (getsockopt (m->sd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        log_msg (LOG_ERR, "Failed to get peer identity: %s", strerror (errno));
        return (-1);
    }
    *uid = cred.uid;
    *gid = cred.gid;
    return (0);
}

#endif /* AUTH_METHOD_SO_PEERCRED */


/*****************************************************************************
 *  LOCAL_PEERCRED sockopt
 *****************************************************************************/

#ifdef AUTH_METHOD_LOCAL_PEERCRED

#include <sys/param.h>                  /* for FreeBSD */
#include <sys/socket.h>
#include <sys/ucred.h>
#include <sys/un.h>                     /* for FreeBSD */

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;                  /* socklen_t is uint32_t in Posix.1g */
#endif /* !HAVE_SOCKLEN_T */

int
auth_recv (m_msg_t m, uid_t *uid, gid_t *gid)
{
    struct xucred cred;
    socklen_t len = sizeof (cred);

    if (getsockopt (m->sd, 0, LOCAL_PEERCRED, &cred, &len) < 0) {
        log_msg (LOG_ERR, "Failed to get peer identity: %s", strerror (errno));
        return (-1);
    }
    if (cred.cr_version != XUCRED_VERSION) {
        log_msg (LOG_ERR, "Failed to get peer identity: invalid xucred v%d",
            cred.cr_version);
        return (-1);
    }
    *uid = cred.cr_uid;
    *gid = cred.cr_gid;
    return (0);
}

#endif /* AUTH_METHOD_LOCAL_PEERCRED */


/*****************************************************************************
 *  strrecvfd struct (mkfifo)
 *****************************************************************************/

#ifdef AUTH_METHOD_RECVFD_MKFIFO

#include <assert.h>
#include <fcntl.h>                      /* open, O_RDONLY */
#include <stdlib.h>                     /* free */
#include <stropts.h>                    /* I_RECVFD, struct strrecvfd */
#include <sys/ioctl.h>                  /* ioctl */
#include <sys/stat.h>                   /* mkfifo, S_IWUSR, etc. */

static int _name_auth_pipe (char **pipe_name_p);
static int _send_auth_req (int sd, const char *pipe_name);

int
auth_recv (m_msg_t m, uid_t *uid, gid_t *gid)
{
    char             *pipe_name = NULL;
    int               pipe_fd = -1;
    struct strrecvfd  recvfd;

    if (_name_auth_pipe (&pipe_name) < 0) {
        log_msg (LOG_ERR, "Failed to name auth pipe");
        goto err;
    }
    assert (pipe_name != NULL);
    (void) unlink (pipe_name);          /* in case it already exists */
    /*
     *  The auth pipe must be created in the filesystem before the auth req
     *    is sent to the client in order to prevent a race condition.
     */
    if (mkfifo (pipe_name, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH) < 0) {
        log_msg (LOG_ERR, "Failed to create auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (_send_auth_req (m->sd, pipe_name) < 0) {
        log_msg (LOG_ERR, "Failed to send auth request");
        goto err;
    }
    /*  This open() blocks until the client opens the fifo for writing.
     *
     *  FIXME: The open() & ioctl() calls could block and lead to a DoS attack.
     */
    if ((pipe_fd = open (pipe_name, O_RDONLY)) < 0) {
        log_msg (LOG_ERR, "Failed to open auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
        goto err;
    }
    if (ioctl (pipe_fd, I_RECVFD, &recvfd) < 0) {
        log_msg (LOG_ERR, "Failed to receive client identity: %s",
            strerror (errno));
        goto err;
    }
    /*  Authentication has succeeded at this point,
     *    so the following "errors" are not considered fatal.
     */
    if (close (recvfd.fd) < 0) {
        log_msg (LOG_WARNING, "Failed to close auth fd from \"%s\": %s",
            pipe_name, strerror (errno));
    }
    if (close (pipe_fd) < 0) {
        log_msg (LOG_WARNING, "Failed to close auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
    }
    if (unlink (pipe_name) < 0) {
        log_msg (LOG_WARNING, "Failed to remove auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
    }
    *uid = recvfd.uid;
    *gid = recvfd.gid;
    free (pipe_name);
    return (0);

err:
    if (pipe_fd >= 0) {
        (void) close (pipe_fd);
    }
    if (pipe_name != NULL) {
        (void) unlink (pipe_name);
        free (pipe_name);
    }
    return (-1);
}

#endif /* AUTH_METHOD_RECVFD_MKFIFO */


/*****************************************************************************
 *  strrecvfd struct (mknod)
 *****************************************************************************/

#ifdef AUTH_METHOD_RECVFD_MKNOD

#include <assert.h>
#include <fcntl.h>                      /* open, O_RDWR */
#include <stdlib.h>                     /* free */
#include <stropts.h>                    /* struct strrecvfd, I_RECVFD */
#include <sys/ioctl.h>                  /* ioctl */
#include <sys/stat.h>                   /* struct stat, mknod, S_IFCHR */
#include <sys/stream.h>                 /* queue_t */
#include <sys/uio.h>                    /* include before stream.h for aix */

static int _ns_pipe (const char *name, int fds[2]);
static int _s_pipe (int fd[2]);
static int _name_auth_pipe (char **dst);
static int _send_auth_req (int sd, const char *pipe_name);

int
auth_recv (m_msg_t m, uid_t *uid, gid_t *gid)
{
    char             *pipe_name = NULL;
    int               pipe_fds[2] = {-1, -1};
    struct strrecvfd  recvfd;

    if (_name_auth_pipe (&pipe_name) < 0) {
        log_msg (LOG_ERR, "Failed to name auth pipe");
        goto err;
    }
    assert (pipe_name != NULL);
    /*
     *  The auth pipe must be created in the filesystem before the auth req
     *    is sent to the client in order to prevent a race condition.
     */
    if ((_ns_pipe (pipe_name, pipe_fds)) < 0) {
        log_msg (LOG_ERR, "Failed to create auth pipe \"%s\"", pipe_name);
        goto err;
    }
    if (_send_auth_req (m->sd, pipe_name) < 0) {
        log_msg (LOG_ERR, "Failed to send auth request");
        goto err;
    }
    /*  FIXME: The ioctl() call could block and lead to a DoS attack.
     */
    if (ioctl (pipe_fds[0], I_RECVFD, &recvfd) < 0) {
        log_msg (LOG_ERR, "Failed to receive client identity: %s",
            strerror (errno));
        goto err;
    }
    /*  Authentication has succeeded at this point,
     *    so the following "errors" are not considered fatal.
     */
    if (close (recvfd.fd) < 0) {
        log_msg (LOG_WARNING, "Failed to close auth fd from \"%s\": %s",
            pipe_name, strerror (errno));
    }
    if (close (pipe_fds[0]) < 0) {
        log_msg (LOG_WARNING,
            "Failed to close auth pipe \"%s\" for reading: %s",
            pipe_name, strerror (errno));
    }
    if (close (pipe_fds[1]) < 0) {
        log_msg (LOG_WARNING,
            "Failed to close auth pipe \"%s\" for writing: %s",
            pipe_name, strerror (errno));
    }
    if (unlink (pipe_name) < 0) {
        log_msg (LOG_WARNING, "Failed to remove auth pipe \"%s\": %s",
            pipe_name, strerror (errno));
    }
    *uid = recvfd.uid;
    *gid = recvfd.gid;
    free (pipe_name);
    return (0);

err:
    if (pipe_fds[0] >= 0) {
        (void) close (pipe_fds[0]);
    }
    if (pipe_fds[1] >= 0) {
        (void) close (pipe_fds[1]);
    }
    if (pipe_name != NULL) {
        (void) unlink (pipe_name);
        free (pipe_name);
    }
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
    (void) unlink (name);
    /*
     *  Determine the major/minor device numbers of one end of the pipe.
     */
    if (fstat (fd[1], &stbuf) < 0) {
        (void) close (fd[0]);
        (void) close (fd[1]);
        return (-1);
    }
    /*  Create the filesystem entry by assigning the [name] to one end
     *    of the pipe.  This requires root privileges.
     */
    if (mknod (name, S_IFCHR | 0666, stbuf.st_rdev) < 0) {
        (void) close (fd[0]);
        (void) close (fd[1]);
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
        (void) close (fd[0]);
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
        (void) close (fd[0]);
        (void) close (fd[1]);
        return (-1);
    }
    return (0);
}

#endif /* AUTH_METHOD_RECVFD_MKNOD */


/*****************************************************************************
 *  strrecvfd struct (common)
 *****************************************************************************/

#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)

#include <assert.h>
#include <stdio.h>                      /* snprintf */
#include <stdlib.h>                     /* malloc, free */
#include <string.h>                     /* memset, strlen, strdup */
#include "conf.h"
#include "random.h"                     /* random_pseudo_bytes */
#include "str.h"                        /* strbin2hex */

static int
_name_auth_pipe (char **pipe_name_p)
{
/*  Creates a unique filename for the authentication pipe, storing the result
 *    in a newly-allocated string referenced by [pipe_name_p].
 *  The caller is responsible for freeing the string returned by [pipe_name_p].
 *  The auth pipe name is of the form "AUTH_PIPE_DIR/.munge-RANDOM.pipe".
 *  Returns 0 on success, -1 on error.
 */
    unsigned char *nonce_bin = NULL;
    int            nonce_bin_len;
    char          *nonce_asc = NULL;
    int            nonce_asc_len;
    char          *dst = NULL;
    int            dst_len;
    int            n;

    *pipe_name_p = NULL;
    assert (conf->auth_rnd_bytes > 0);
    assert (conf->auth_server_dir != NULL);

    nonce_bin_len = conf->auth_rnd_bytes;
    if (!(nonce_bin = malloc (nonce_bin_len))) {
        goto err;
    }
    nonce_asc_len = (2 * nonce_bin_len) + 1;
    if (!(nonce_asc = malloc (nonce_asc_len))) {
        goto err;
    }
    dst_len = strlen (conf->auth_server_dir)
        + 8                             /* strlen ("/.munge-") */
        + (2 * conf->auth_rnd_bytes)
        + 6;                            /* strlen (".pipe") + "\0" */
    if (!(dst = malloc (dst_len))) {
        goto err;
    }
    random_pseudo_bytes (nonce_bin, nonce_bin_len);
    if (!(strbin2hex (nonce_asc, nonce_asc_len, nonce_bin, nonce_bin_len))) {
        goto err;
    }
    n = snprintf (dst, dst_len, "%s/.munge-%s.pipe",
        conf->auth_server_dir, nonce_asc);
    if ((n < 0) || (n >= dst_len)) {
        goto err;
    }
    free (nonce_bin);
    free (nonce_asc);
    *pipe_name_p = dst;
    return (0);

err:
    if (nonce_bin) {
        free (nonce_bin);
    }
    if (nonce_asc) {
        free (nonce_asc);
    }
    if (dst) {
        free (dst);
    }
    return (-1);
}

static int
_send_auth_req (int sd, const char *pipe_name)
{
/*  Sends an authentication request to the client on the established
 *    socket [sd] using [pipe_name] as the authentication pipe to use
 *    for sending an fd across.
 *  Returns 0 on success, -1 on error.
 *
 *  The authentication request message contains the authentication pipe name
 *    for the client to send a file descriptor across, as well as the directory
 *    name in which to create the authentication file corresponding to the file
 *    descriptor being sent.
 */
    m_msg_t      m;
    munge_err_t  e;

    if ((e = m_msg_create (&m)) != EMUNGE_SUCCESS) {
        goto end;
    }
    if ((e = m_msg_bind (m, sd)) != EMUNGE_SUCCESS) {
        goto end;
    }
    m->auth_s_str = (char *) pipe_name;
    m->auth_s_len = strlen (m->auth_s_str) + 1;
    m->auth_s_is_copy = 1;
    m->auth_c_str = conf->auth_client_dir;
    m->auth_c_len = strlen (m->auth_c_str) + 1;
    m->auth_c_is_copy = 1;

    e = m_msg_send (m, MUNGE_MSG_AUTH_FD_REQ, 0);

end:
    if (m) {
        m->sd = -1;                     /* prevent close by m_msg_destroy() */
        m_msg_destroy (m);
    }
    return (e == EMUNGE_SUCCESS ? 0 : -1);
}

#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */
