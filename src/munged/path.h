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
/*
 *  Canonicalizes the path [src], returning an absolute pathname in the
 *    buffer [dst] of length [dstlen].
 *  Canonicalization expands all symbolic links and resolves references to
 *    '/./', '/../', and extra '/' characters.
 *  Returns the strlen() of the canonicalized path; if retval >= dstlen,
 *    truncation occurred.
 *  Returns -1 on error (with errno set).
 */

int path_dirname (const char *src, char *dst, size_t dstlen);
/*
 *  Copies the parent directory name of [src] into the buffer [dst] of
 *    length [dstlen].  Trailing '/' characters in the path are removed.
 *    If [src] does not contain a '/', then [dst] is set to the string ".".
 *  Returns 0 on success, or -1 on error (with errno set).
 */

int path_is_accessible (const char *path, char *errbuf, size_t errbuflen);
/*
 *  Checks if the specified [path] is accessible by all users.
 *  Returns 1 if all checks pass, 0 if any checks fail, or -1 on error
 *    (with errno set).
 *  If [errbuf] is non-NULL, a message describing the inaccessibility or error
 *    will be written to the buffer [errbuf] of length [errbuflen].
 */

int path_is_secure (const char *path, char *errbuf, size_t errbuflen,
    path_security_flag_t flags);
/*
 *  Checks if the specified [path] is secure, ensuring that the base directory
 *    cannot be modified by anyone other than the current user, the trusted
 *    group (if set), or root.
 *  Returns 1 if all checks pass, 0 if any checks fail, or -1 on error
 *    (with errno set).
 *  If [errbuf] is non-NULL, a message describing the insecurity or error
 *    will be written to the buffer [errbuf] of length [errbuflen].
 */

int path_get_trusted_group (gid_t *gid_ptr);
/*
 *  Gets the "trusted group" for permission checks on a directory hierarchy,
 *    storing the GID at [gid_ptr].
 *  Returns 0 on success with the "trusted group" GID stored at [gid_ptr]
 *    (if non-NULL).  Returns -1 on error without updating [gid_ptr].
 *  Warning: Not thread-safe.
 */

int path_set_trusted_group (const char *group);
/*
 *  Sets the "trusted group" for permission checks on a directory hierarchy.
 *    Directories with write permissions for group are allowed if they are
 *    owned by the trusted group.
 *  The [group] string can specify either a group name or GID.
 *    If [group] is NULL, the trusted group setting is cleared.
 *  Returns 0 on success, or -1 on error.
 *  Warning: Not thread-safe.
 */


#endif /* !PATH_H */
