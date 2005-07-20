/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2004-2005 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
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
