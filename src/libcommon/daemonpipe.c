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

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "daemonpipe.h"
#include "fd.h"


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

static int _daemonpipe_fd_read = -1;
static int _daemonpipe_fd_write = -1;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  daemonpipe_create
 *  Create a "daemonpipe" for IPC synchronization between the parent process
 *    and its double-forked grandchild process during daemonization.
 *  Return 0 on success, or -1 on error with errno set.
 *  The parent process will block upon reading from this pipe until signaled by
 *    a write from its child or grandchild process, after which it will exit.
 *  The grandchild process will write to this pipe once startup is complete.
 *  If startup fails, an error message will be written to the pipe by the child
 *    or grandchild process in order for the parent process to relay it to
 *    stderr before exiting.
 */
int
daemonpipe_create (void)
{
    int fd_pipe [2];
    int errno_bak;

    if (pipe (fd_pipe) < 0) {
        return (-1);
    }
    if (daemonpipe_close_reads () < 0) {
        goto err;
    }
    if (daemonpipe_close_writes () < 0) {
        goto err;
    }
    _daemonpipe_fd_read = fd_pipe[0];
    _daemonpipe_fd_write = fd_pipe[1];
    return (0);

err:
    errno_bak = errno;
    (void) close (fd_pipe[0]);
    (void) close (fd_pipe[1]);
    errno = errno_bak;
    return (-1);
}


/*  daemonpipe_close_reads
 *  Close the read-end of the daemonpipe.
 *  Return 0 on success, or -1 on error with errno set.
 *  This should be called by the child process after having been forked.
 */
int
daemonpipe_close_reads (void)
{
    if (_daemonpipe_fd_read < 0) {
        return (0);
    }
    if (close (_daemonpipe_fd_read) < 0) {
        return (-1);
    }
    _daemonpipe_fd_read = -1;
    return (0);
}


/*  daemonpipe_close_writes
 *  Close the write-end of the daemonpipe.
 *  Return 0 on success, or -1 on error with errno set.
 *  This should be called by the parent process after forking.
 *  This should be called by the grandchild process once startup is complete.
 *    It will signal the parent process blocked on daemonpipe_read().
 */
int
daemonpipe_close_writes (void)
{
    if (_daemonpipe_fd_write < 0) {
        return (0);
    }
    if (close (_daemonpipe_fd_write) < 0) {
        return (-1);
    }
    _daemonpipe_fd_write = -1;
    return (0);
}


/*  daemonpipe_read
 *  Read a status code into [statusptr], a priority level into [priorityptr],
 *    and an error string into the buffer [dstbufptr] of length [dstbuflen].
 *    A status of 0 indicates success.
 *  Return 0 on success, or -1 on error with errno set.
 *  This should be called by the parent process once it is ready to block and
 *    wait for its grandchild process to complete startup/initialization.
 */
int
daemonpipe_read (int *statusptr, int *priorityptr,
        char *dstbufptr, size_t dstbuflen)
{
    signed char c;
    char        buf [1024];
    ssize_t     n, m;

    if ((statusptr == NULL) || (priorityptr == NULL) || (dstbufptr == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    if (_daemonpipe_fd_read < 0) {
        errno = EBADF;
        return (-1);
    }
    /*  Initialize result parms in case of early return.
     */
    *statusptr = -1;
    *priorityptr = 0;
    if (dstbuflen > 0) {
        dstbufptr[0] = '\0';
    }
    /*  Read status.
     */
    n = fd_read_n (_daemonpipe_fd_read, &c, sizeof (c));
    if (n < 0) {
        return (-1);
    }
    else if (n == 0) {                  /* if EOF, no err so return success */
        *statusptr = 0;
        return (0);
    }
    else if (n > 0) {
        *statusptr = (int) c;
    }
    /*  Read priority.
     */
    n = fd_read_n (_daemonpipe_fd_read, &c, sizeof (c));
    if (n < 0) {
        return (-1);
    }
    else if (n == 0) {
        return (0);
    }
    else if (n > 0) {
        *priorityptr = (int) c;
    }
    /*  Read error message.
     */
    n = fd_read_n (_daemonpipe_fd_read, buf, sizeof (buf));
    if (n < 0) {
        return (-1);
    }
    else if ((n > 0) && (dstbuflen > 0)) {
        /*
         *  Ensure buf[] is null-terminated.
         */
        m = (n < sizeof (buf)) ? n : sizeof (buf) - 1;
        buf[m] = '\0';
        /*
         *  Remove trailing LF if present.
         */
        m = strlen (buf) - 1;
        if ((m >= 0) && (buf[m] == '\n')) {
            buf[m] = '\0';
        }
        strncpy (dstbufptr, buf, dstbuflen);
        dstbufptr[dstbuflen - 1] = '\0';
    }
    return (0);
}


/*  daemonpipe_write
 *  Write a status code and an error message string [msg] at the specified
 *    [priority] level to the daemonpipe.  A status of 0 indicates success.
 *  Return 0 on success, or -1 on error with errno set.
 *  This should be called by the child or grandchild process if an error
 *    message needs to be relayed to the stderr of the parent process.
 *    It will signal the parent process blocked on daemonpipe_read().
 */
int
daemonpipe_write (int status, int priority, const char *msg)
{
    signed char c;
    ssize_t     len;
    ssize_t     n;

    if (_daemonpipe_fd_write < 0) {
        errno = EBADF;
        return (-1);
    }
    /*  Write status.
     */
    c = (signed char) status;
    len = sizeof (c);
    n = fd_write_n (_daemonpipe_fd_write, &c, len);
    if (n != len) {
        return (-1);
    }
    /*  Write priority.
     */
    c = (signed char) priority;
    len = sizeof (c);
    n = fd_write_n (_daemonpipe_fd_write, &c, len);
    if (n != len) {
        return (-1);
    }
    /*  Write error message.  If no message is specified, write a null string.
     */
    if (msg == NULL) {
        msg = "\0";
    }
    len = strlen (msg) + 1;
    n = fd_write_n (_daemonpipe_fd_write, msg, len);
    if (n != len) {
        return (-1);
    }
    return (0);
}
