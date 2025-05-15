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


#ifndef PATH_H
#define PATH_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <limits.h>
#include <unistd.h>

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif /* !PATH_MAX */


typedef enum path_security_flags {
    PATH_SECURITY_NO_FLAGS =            0x00,
    PATH_SECURITY_IGNORE_GROUP_WRITE =  0x01
} path_security_flag_t;


int path_canonicalize (const char *src, char *dst, int dstlen);

int path_dirname (const char *src, char *dst, size_t dstlen);

int path_is_accessible (const char *path, char *errbuf, size_t errbuflen);

int path_is_secure (const char *path, char *errbuf, size_t errbuflen,
    path_security_flag_t flags);

int path_get_trusted_group (gid_t *gid_ptr);

int path_set_trusted_group (const char *group);


#endif /* !PATH_H */
