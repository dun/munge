/*****************************************************************************
 *  Copyright (C) 2007-2025 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
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
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include "fd.h"


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static int _fd_get_poll_timeout (const struct timeval *when);


/*****************************************************************************
 *  Public Functions for I/O
 *****************************************************************************/

/*  Reads up to [n] bytes from [fd] into [buf].
 *  Returns the number of bytes read, 0 on EOF, or -1 on error.
 */
ssize_t
fd_read_n (int fd, void *buf, size_t n)
{
    unsigned char *p;
    size_t         nleft;
    ssize_t        nread;

    p = buf;
    nleft = n;
    while (nleft > 0) {
        if ((nread = read (fd, p, nleft)) < 0) {
            if (errno == EINTR)
                continue;
            else
                return (-1);
        }
        else if (nread == 0) {          /* EOF */
            break;
        }
        nleft -= nread;
        p += nread;
    }
    return (n - nleft);
}


/*  Writes [n] bytes from [buf] to [fd].
 *  Returns the number of bytes written, or -1 on error.
 */
ssize_t
fd_write_n (int fd, const void *buf, size_t n)
{
    const unsigned char *p;
    size_t               nleft;
    ssize_t              nwritten;

    p = buf;
    nleft = n;
    while (nleft > 0) {
        if ((nwritten = write (fd, p, nleft)) < 0) {
            if (errno == EINTR)
                continue;
            else
                return (-1);
        }
        nleft -= nwritten;
        p += nwritten;
    }
    return (n);
}


/*  Reads up to [n] bytes from [fd] into [buf], timing-out at [when]
 *    which specifies a ceiling on the time for which the call will block.
 *    This ceiling is an absolute timeout in seconds and microseconds since
 *    the Epoch.  If [when] is NULL, the read will block until [n] bytes
 *    have been read or an EOF is encountered.
 *  If [do_skip_first_poll] is enabled, the poll() preceding the read()
 *    will be skipped on the first iteration of the loop; this optimization
 *    should only be enabled if [fd] is nonblocking.
 *  Returns the number of bytes read, or -1 on error.  A timeout is not
 *    an error.  If a timeout has occurred, errno will be set to ETIMEDOUT.
 *    The caller should reset errno beforehand when checking for timeout.
 */
ssize_t
fd_timed_read_n (int fd, void *buf, size_t n,
                 const struct timeval *when, int do_skip_first_poll)
{
    unsigned char *p;
    int            msecs;
    struct pollfd  pfd;
    int            nfd;
    size_t         nleft;
    ssize_t        nread;

    if ((fd < 0) || (buf == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    p = buf;
    nleft = n;
    pfd.fd = fd;
    pfd.events = POLLIN;

    if (do_skip_first_poll && (nleft > 0)) {
        msecs = -1;
        goto read_me;
    }
    while (nleft > 0) {

        msecs = _fd_get_poll_timeout (when);
        nfd = poll (&pfd, 1, msecs);

        if (nfd < 0) {
            if ((errno == EINTR) || (errno == EAGAIN))
                continue;
            else
                return (-1);
        }
        else if (nfd == 0) {            /* timeout */
            errno = ETIMEDOUT;
            break;
        }
        else if (pfd.revents & POLLNVAL) {
            errno = EBADF;
            return (-1);
        }
        else if (pfd.revents & POLLERR) {
            errno = EIO;
            return (-1);
        }
        assert (pfd.revents & POLLIN);

read_me:
        nread = read (fd, p, nleft);
        if (nread < 0) {
            if ((errno == EINTR) || (errno == EAGAIN))
                continue;
            else
                return (-1);
        }
        else if (nread == 0) {          /* EOF */
            break;
        }
        nleft -= nread;
        p += nread;

        if (msecs == 0) {
            break;
        }
    }
    return (n - nleft);
}


/*  Writes [n] bytes from [buf] to [fd], timing-out at [when] which
 *    specifies a ceiling on the time for which the call will block.
 *    This ceiling is an absolute timeout in seconds and microseconds since
 *    the Epoch.  If [when] is NULL, the write will block until [n] bytes
 *    have been written or a POLLHUP is encountered.
 *  If [do_skip_first_poll] is enabled, the poll() preceding the write()
 *    will be skipped on the first iteration of the loop; this optimization
 *    should only be enabled if [fd] is nonblocking.
 *  Returns the number of bytes written, or -1 on error.  A timeout is not
 *    an error.  If a timeout has occurred, errno will be set to ETIMEDOUT.
 *    The caller should reset errno beforehand when checking for timeout.
 */
ssize_t
fd_timed_write_n (int fd, const void *buf, size_t n,
                  const struct timeval *when, int do_skip_first_poll)
{
    const unsigned char *p;
    int                  msecs;
    struct pollfd        pfd;
    int                  nfd;
    size_t               nleft;
    ssize_t              nwritten;

    if ((fd < 0) || (buf == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    p = buf;
    nleft = n;
    pfd.fd = fd;
    pfd.events = POLLOUT;

    if (do_skip_first_poll && (nleft > 0)) {
        msecs = -1;
        goto write_me;
    }
    while (nleft > 0) {

        msecs = _fd_get_poll_timeout (when);
        nfd = poll (&pfd, 1, msecs);

        if (nfd < 0) {
            if ((errno == EINTR) || (errno == EAGAIN))
                continue;
            else
                return (-1);
        }
        else if (nfd == 0) {            /* timeout */
            errno = ETIMEDOUT;
            break;
        }
        else if (pfd.revents & POLLHUP) {
            break;
        }
        else if (pfd.revents & POLLNVAL) {
            errno = EBADF;
            return (-1);
        }
        else if (pfd.revents & POLLERR) {
            errno = EIO;
            return (-1);
        }
        assert (pfd.revents & POLLOUT);

write_me:
        nwritten = write (fd, p, nleft);
        if (nwritten < 0) {
            if ((errno == EINTR) || (errno == EAGAIN))
                continue;
            else
                return (-1);
        }
        nleft -= nwritten;
        p += nwritten;

        if (msecs == 0) {
            break;
        }
    }
    return (n - nleft);
}


/*  Writes the [iov] vector of [iov_cnt] blocks to [fd], timing-out at [when]
 *    which specifies a ceiling on the time for which the call will block.
 *    This ceiling is an absolute timeout in seconds and microseconds since
 *    the Epoch.  If [when] is NULL, the write will block until [n] bytes
 *    have been written or a POLLHUP is encountered.
 *  If [do_skip_first_poll] is enabled, the poll() preceding the writev()
 *    will be skipped on the first iteration of the loop; this optimization
 *    should only be enabled if [fd] is nonblocking.
 *  Returns the number of bytes written, or -1 on error.  A timeout is not
 *    an error.  If a timeout has occurred, errno will be set to ETIMEDOUT.
 *    The caller should reset errno beforehand when checking for timeout.
 */
ssize_t
fd_timed_write_iov (int fd, const struct iovec *iov_orig, int iov_cnt,
                    const struct timeval *when, int do_skip_first_poll)
{
    int            iov_mem_len;
    struct iovec  *iov;
    int            i;
    size_t         n, nleft, iov_len;
    struct pollfd  pfd;
    int            nfd;
    int            msecs;
    ssize_t        nwritten;

    if ((fd < 0) || (iov_orig == NULL) || (iov_cnt <= 0)) {
        errno = EINVAL;
        return (-1);
    }
    /*  Create copy of iovec for modification to handle retrying short writes.
     */
    iov_mem_len = sizeof (struct iovec) * iov_cnt;
    iov = malloc (iov_mem_len);
    if (iov == NULL) {
        errno = ENOMEM;
        return (-1);
    }
    memcpy (iov, iov_orig, iov_mem_len);

    for (i = 0, n = 0; i < iov_cnt; i++) {
        n += iov[i].iov_len;
    }
    nleft = iov_len = n;
    pfd.fd = fd;
    pfd.events = POLLOUT;

    if (do_skip_first_poll && (nleft > 0)) {
        msecs = -1;
        goto writev_me;
    }
    while (nleft > 0) {

        msecs = _fd_get_poll_timeout (when);
        nfd = poll (&pfd, 1, msecs);

        if (nfd < 0) {
            if ((errno == EINTR) || (errno == EAGAIN))
                continue;
            else
                goto err;
        }
        else if (nfd == 0) {            /* timeout */
            errno = ETIMEDOUT;
            break;
        }
        else if (pfd.revents & POLLHUP) {
            break;
        }
        else if (pfd.revents & POLLNVAL) {
            errno = EBADF;
            goto err;
        }
        else if (pfd.revents & POLLERR) {
            errno = EIO;
            goto err;
        }
        assert (pfd.revents & POLLOUT);

writev_me:
        nwritten = writev (fd, iov, iov_cnt);
        if (nwritten < 0) {
            if ((errno == EINTR) || (errno == EAGAIN))
                continue;
            else
                goto err;
        }
        nleft -= nwritten;

        if (msecs == 0) {
            break;
        }
        for (i = 0; (i < iov_cnt) && (nwritten > 0); i++) {
            n = (nwritten > iov[i].iov_len) ? iov[i].iov_len : nwritten;
            if (n == 0)
                continue;
            nwritten -= n;
            iov[i].iov_len -= n;
            iov[i].iov_base = (char *) iov[i].iov_base + n;
        }
    }
    free (iov);
    return (iov_len - nleft);

err:
    free (iov);
    return (-1);
}


/*  Reads at most [maxlen-1] bytes up to a newline from [fd] into [buf].
 *  The [buf] is guaranteed to be null-terminated and will contain the
 *    newline if it is encountered within [maxlen-1] bytes.
 *  Returns the number of bytes read, 0 on EOF, or -1 on error.
 */
ssize_t
fd_read_line (int fd, void *buf, size_t maxlen)
{
    ssize_t n, rc;
    unsigned char c, *p;

    n = 0;
    p = buf;
    while (n < maxlen - 1) {            /* -1 for terminating null byte */

        if ((rc = read (fd, &c, 1)) == 1) {
            n++;
            *p++ = c;
            if (c == '\n')
                break;                  /* store newline, like fgets() */
        }
        else if (rc == 0) {
            if (n == 0)                 /* EOF, no data read */
                return (0);
            else                        /* EOF, some data read */
                break;
        }
        else {
            if (errno == EINTR)
                continue;
            return (-1);
        }
    }

    *p = '\0';                          /* null-terminate */
    return (n);
}


/*****************************************************************************
 *  Public Functions for Attributes
 *****************************************************************************/

/*  Sets the file descriptor [fd] to be closed on exec().
 *  Returns 0 on success, or -1 on error.
 */
int
fd_set_close_on_exec (int fd)
{
    if (fd < 0) {
        errno = EINVAL;
        return (-1);
    }
    if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0) {
        return (-1);
    }
    return (0);
}


/*  Sets the file descriptor [fd] for nonblocking I/O.
 *  Returns 0 on success, or -1 on error.
 */
int
fd_set_nonblocking (int fd)
{
    int fval;

    if (fd < 0) {
        errno = EINVAL;
        return (-1);
    }
    if ((fval = fcntl (fd, F_GETFL, 0)) < 0) {
        return (-1);
    }
    if (fcntl (fd, F_SETFL, fval | O_NONBLOCK) < 0) {
        return (-1);
    }
    return (0);
}


/*  Returns >0 if the file descriptor [fd] is set for nonblocking I/O,
 *     0 if not set, or -1 on error (with errno set appropriately).
 */
int
fd_is_nonblocking (int fd)
{
    int fval;

    if (fd < 0) {
        errno = EINVAL;
        return (-1);
    }
    if ((fval = fcntl (fd, F_GETFL, 0)) < 0) {
        return (-1);
    }
    return ((fval & O_NONBLOCK) ? 1 : 0);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static int
_fd_get_poll_timeout (const struct timeval *when)
{
/*  Returns the poll() timeout value for the number of milliseconds between now
 *    and [when] (which specifies an absolute time in seconds and microseconds
 *    since the Epoch), 0 if [when] is in the past, or -1 if [when] is NULL
 *    (indicating poll() should wait indefinitely).
 */
    struct timeval now;
    int            msecs;

    if (when == NULL) {
        return (-1);
    }
    if ((when->tv_sec == 0) && (when->tv_usec == 0)) {
        return (0);
    }
    /*  POSIX says gettimeofday() can't fail, but just in case ...
     */
    if (gettimeofday (&now, NULL) < 0) {
        return (0);
    }
    /*  Round up to the next millisecond.
     *  XXX: msecs can overflow/underflow if [when] is too far from now.
     */
    msecs = ( (when->tv_sec  - now.tv_sec)        * 1000 ) +
            ( (when->tv_usec - now.tv_usec + 999) / 1000 ) ;
    /*
     *  Return 0 if [when] is in the past to indicate poll() should not block.
     */
    return ((msecs < 0) ? 0 : msecs);
}
