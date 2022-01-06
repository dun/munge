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


#ifndef FD_H
#define FD_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>


ssize_t fd_read_n (int fd, void *buf, size_t n);
/*
 *  Reads up to [n] bytes from [fd] into [buf].
 *  Returns the number of bytes read, 0 on EOF, or -1 on error.
 */

ssize_t fd_write_n (int fd, const void *buf, size_t n);
/*
 *  Writes [n] bytes from [buf] to [fd].
 *  Returns the number of bytes written, or -1 on error.
 */

ssize_t fd_timed_read_n (int fd, void *buf, size_t n,
        const struct timeval *when, int do_skip_first_poll);
/*
 *  Reads up to [n] bytes from [fd] into [buf], timing-out at [when]
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

ssize_t fd_timed_write_n (int fd, const void *buf, size_t n,
        const struct timeval *when, int do_skip_first_poll);
/*
 *  Writes [n] bytes from [buf] to [fd], timing-out at [when] which
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

ssize_t fd_timed_write_iov (int fd, const struct iovec *iov, int iov_cnt,
        const struct timeval *when, int do_skip_first_poll);
/*
 *  Writes the [iov] vector of [iov_cnt] blocks to [fd], timing-out at [when]
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

ssize_t fd_read_line (int fd, void *buf, size_t maxlen);
/*
 *  Reads at most [maxlen-1] bytes up to a newline from [fd] into [buf].
 *  The [buf] is guaranteed to be NUL-terminated and will contain the
 *    newline if it is encountered within [maxlen-1] bytes.
 *  Returns the number of bytes read, 0 on EOF, or -1 on error.
 */

int fd_set_close_on_exec (int fd);
/*
 *  Sets the file descriptor [fd] to be closed on exec().
 *  Returns 0 on success, or -1 on error.
 */

int fd_set_nonblocking (int fd);
/*
 *  Sets the file descriptor [fd] for nonblocking I/O.
 *  Returns 0 on success, or -1 on error.
 */

int fd_is_nonblocking (int fd);
/*
 *  Returns >0 if the file descriptor [fd] is set for nonblocking I/O,
 *     0 if not set, or -1 on error (with errno set appropriately).
 */


#endif /* !FD_H */
