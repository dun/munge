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

ssize_t fd_write_n (int fd, const void *buf, size_t n);

ssize_t fd_timed_read_n (int fd, void *buf, size_t n,
        const struct timeval *when, int do_skip_first_poll);

ssize_t fd_timed_write_n (int fd, const void *buf, size_t n,
        const struct timeval *when, int do_skip_first_poll);

ssize_t fd_timed_write_iov (int fd, const struct iovec *iov, int iov_cnt,
        const struct timeval *when, int do_skip_first_poll);

ssize_t fd_read_line (int fd, void *buf, size_t maxlen);

int fd_set_close_on_exec (int fd);

int fd_set_nonblocking (int fd);

int fd_is_nonblocking (int fd);


#endif /* !FD_H */
