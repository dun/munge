/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory.
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
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


#ifndef PATH_H
#define PATH_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */


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

int path_is_secure (const char *path, char *errbuf, size_t errbuflen);
/*
 *  Checks if the specified [path] is secure, ensuring that the base directory
 *    cannot be modified by anyone other than the current user or root.
 *  Returns 1 if all checks pass, 0 if any checks fail, or -1 on error
 *    (with errno set).
 *  If [errbuf] is non-NULL, a message describing the insecurity or error
 *    will be written to the buffer [errbuf] of length [errbuflen].
 */


#endif /* !PATH_H */
