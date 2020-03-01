/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2020 Lawrence Livermore National Security, LLC.
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
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  FIXME
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
path_canonicalize (const char *src, char *dst, size_t dstlen)
{
    char dirbuf [PATH_MAX];
    const char *p, *q;
    const char *dir, *file;
    size_t dirlen, filelen;
    char *r;

    if (!src || !dst || (dstlen < PATH_MAX)) {
        errno = EINVAL;
        return -1;
    }
    if (*src == '\0') {
        errno = ENOENT;
        return -1;
    }
    p = strrchr (src, '/');
    q = p ? p + 1 : src;

    if ((q[0] == '.') && (q[1] == '\0' || (q[1] == '.' && q[2] == '\0'))) {
        dir = src;
        file = "";
    }
    else if (p == NULL) {
        dir = ".";
        file = src;
    }
    else {
        dirlen = p - src + 1;
        if (dirlen >= sizeof (dirbuf)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        strncpy (dirbuf, src, dirlen);
        dirbuf[dirlen] = '\0';
        dir = dirbuf;
        file = p + 1;
    }
    r = realpath (dir, dst);
    if (r == NULL) {
        return -1;
    }
    if (*file) {
        dirlen = strlen (dst);
        filelen = strlen (file);
        if ((dirlen + 1 + filelen) >= dstlen) {
            errno = ENAMETOOLONG;
            return -1;
        }
        r = dst + dirlen;
        if (*(r - 1) != '/') {
            *r++ = '/';
        }
        strncpy (r, file, filelen + 1);
    }
    return 0;
}
