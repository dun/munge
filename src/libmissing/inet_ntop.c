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

#ifndef HAVE_INET_NTOP

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include "inet_ntop.h"

const char *
inet_ntop (int af, const void *src, char *dst, socklen_t cnt)
{
    const unsigned char *p = src;
    int n;

    if (af != AF_INET) {
        errno = EAFNOSUPPORT;
        return (NULL);
    }
    if (!src || !dst) {
        errno = EINVAL;
        return (NULL);
    }
    n = snprintf (dst, cnt, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    if ((n < 0) || (n >= cnt)) {
        errno = ENOSPC;
        return (NULL);
    }
    return (dst);
}

#endif /* !HAVE_INET_NTOP */
