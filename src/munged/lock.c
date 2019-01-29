/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2018 Lawrence Livermore National Security, LLC.
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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "conf.h"
#include "log.h"
#include "str.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void _lock_create_name (conf_t conf);

static void _lock_stat (int fd, const char *name);

static int _lock_set (int fd);

static pid_t _lock_is_set (int fd);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
lock_create (conf_t conf)
{
/*  Creates a lockfile to ensure exclusive access to the Unix domain socket.
 */
    int    rv;
    mode_t mask;

    if (conf == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create lock: conf undefined");
    }
    _lock_create_name (conf);

    /*  If unable to unlink() the lockfile, log a warning instead of an error
     *    since this code path is being executed with "--force".
     */
    if (conf->got_force) {
        rv = unlink (conf->lockfile_name);
        if ((rv < 0) && (errno != ENOENT)) {
            log_msg (LOG_WARNING, "Failed to remove \"%s\": %s",
                    conf->lockfile_name, strerror (errno));
        }
    }
    if (conf->lockfile_fd >= 0) {
        rv = close (conf->lockfile_fd);
        if (rv < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to close \"%s\"", conf->lockfile_name);
        }
    }
    mask = umask (0);
    conf->lockfile_fd = open (conf->lockfile_name,
            O_CREAT | O_TRUNC | O_WRONLY, S_IWUSR);
    umask (mask);

    /*  If the lockfile creation fails, either log an error and exit,
     *    or log a warning and immediately return.
     */
    if (conf->lockfile_fd < 0) {
        log_err_or_warn (conf->got_force,
                "Failed to create \"%s\": %s", conf->lockfile_name,
                strerror (errno));
        return;                         /* no lock, so nothing more to do */
    }
    _lock_stat (conf->lockfile_fd, conf->lockfile_name);

    rv = _lock_set (conf->lockfile_fd);
    if (rv < 0) {
        log_err_or_warn (conf->got_force,
                "Failed to lock \"%s\"", conf->lockfile_name);
    }
    else if (rv > 0) {

        pid_t pid = _lock_is_set (conf->lockfile_fd);

        if (pid < 0) {
            log_err_or_warn (conf->got_force,
                    "Failed to test \"%s\": %s", conf->lockfile_name,
                    strerror (errno));
        }
        else if (pid > 0) {
            log_err_or_warn (conf->got_force,
                    "Failed to lock \"%s\": pid %d bound to socket \"%s\"",
                    conf->lockfile_name, pid, conf->socket_name);
        }
        else {
            /*  _lock_set() reported lock was held by another process,
             *    but _lock_is_set() found no lock.  TOCTOU.
             */
            log_err_or_warn (conf->got_force,
                    "Failed to lock \"%s\": Inconsistent lock state",
                    conf->lockfile_name);
        }
    }
    return;
}


pid_t
lock_query (conf_t conf)
{
/*  Tests the lockfile for an exclusive advisory lock to see if
 *    another process is already holding it.
 *  Returns the pid of a running process (>0) if the lock is held,
 *    0 if the lock is not held, or -1 on error.
 */
    int   rv;
    pid_t pid;

    if (conf == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create lock: conf undefined");
    }
    _lock_create_name (conf);

    if (conf->lockfile_fd >= 0) {
        rv = close (conf->lockfile_fd);
        if (rv < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to close \"%s\"", conf->lockfile_name);
        }
    }
    conf->lockfile_fd = open (conf->lockfile_name, O_WRONLY, S_IWUSR);
    if (conf->lockfile_fd < 0) {
        return (-1);
    }
    pid = _lock_is_set (conf->lockfile_fd);
    return (pid);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void
_lock_create_name (conf_t conf)
{
/*  Creates the lockfile name based on the socket name.
 */
    assert (conf != NULL);

    if (conf->socket_name == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create lockfile_name: socket_name undefined");
    }
    if (conf->lockfile_name) {
        free (conf->lockfile_name);
    }
    conf->lockfile_name = strdupf ("%s.lock", conf->socket_name);
    if (conf->lockfile_name == NULL) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create lockfile_name");
    }
    return;
}


static void
_lock_stat (int fd, const char *name)
{
/*  Stats the lockfile [name] via the file-descriptor [fd] to prevent TOCTOU
 *    and checks for peculiarities.
 */
    int         rv;
    struct stat st;

    assert (fd >= 0);
    assert (name != NULL);

    rv = fstat (fd, &st);
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate lockfile: cannot stat \"%s\"", name);
    }
    else if (!S_ISREG(st.st_mode)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate lockfile: \"%s\" should be a regular file",
                name);
    }
    else if ((st.st_mode & 07777) != S_IWUSR) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate lockfile: "
                        "\"%s\" should only be writable by user", name);
    }
    else if (st.st_uid != geteuid()) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to validate lockfile: "
                        "\"%s\" should be owned by UID %u",
                name, (unsigned) geteuid());
    }
    return;
}


static int
_lock_set (int fd)
{
/*  Sets an exclusive advisory lock on the open file descriptor 'fd'.
 *  Returns 0 on success, 1 if a conflicting lock is held by another process,
 *    or -1 on error (with errno set).
 */
    struct flock fl;
    int          rv;

    if (fd < 0) {
        errno = EBADF;
        return (-1);
    }
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    rv = fcntl (fd, F_SETLK, &fl);
    if (rv < 0) {
        if ((errno == EACCES) || (errno == EAGAIN)) {
            return (1);
        }
        return (-1);
    }
    return (0);
}


static pid_t
_lock_is_set (int fd)
{
/*  Tests whether an exclusive advisory lock could be obtained for the open
 *    file descriptor 'fd'.
 *  Returns 0 if the file is not locked, >0 for the pid of another process
 *    holding a conflicting lock, or -1 on error (with errno set).
 */
    struct flock fl;
    int          rv;

    if (fd < 0) {
        errno = EBADF;
        return (-1);
    }
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    rv = fcntl (fd, F_GETLK, &fl);
    if (rv < 0) {
        return (-1);
    }
    if (fl.l_type == F_UNLCK) {
        return (0);
    }
    return (fl.l_pid);
}
