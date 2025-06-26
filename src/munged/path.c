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
 *****************************************************************************
 *  Refer to "path.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "path.h"
#include "query.h"


/*****************************************************************************
 *  Internal Variables
 *****************************************************************************/

static gid_t _path_trusted_gid = GID_SENTINEL;


/*****************************************************************************
 *  Internal Prototypes
 *****************************************************************************/

static int _path_set_err (int rc, char *buf, size_t buflen,
    const char *format, ...);


/*****************************************************************************
 *  External Functions
 *****************************************************************************/

/*  Canonicalizes the path [src], returning an absolute pathname in the
 *    buffer [dst] of length [dstlen].
 *  Canonicalization expands all symbolic links and resolves references to
 *    '/./', '/../', and extra '/' characters.
 *  Returns the strlen() of the canonicalized path on success.
 *  Returns -1 on error (with errno set).
 */
int
path_canonicalize (const char *src, char *dst, size_t dstlen)
{
    char buf [PATH_MAX];                /* realpath() requires PATH_MAX bytes */
    size_t buflen;

    if (!src || !*src || !dst) {
        errno = EINVAL;
        return (-1);
    }
    if (!realpath (src, buf)) {
        return (-1);
    }
    if (buf[0] != '/') {
        errno = EINVAL;
        return (-1);
    }
    buflen = strnlen (buf, dstlen);
    if (buflen >= dstlen) {
        errno = ENAMETOOLONG;
        return (-1);
    }
    memcpy (dst, buf, buflen + 1);
    return (buflen);
}


/*  Copies the parent directory name of [src] into the buffer [dst] of
 *    length [dstlen].  Trailing '/' characters in the path are removed.
 *    If [src] does not contain a '/', then [dst] is set to the string ".".
 *  Returns 0 on success, or -1 on error (with errno set).
 */
int
path_dirname (const char *src, char *dst, size_t dstlen)
{
    size_t srclen;
    char *p = NULL;
    enum { start, last_slash, last_word, prev_slash } state = start;

    if (!src || !*src || !dst) {
        errno = EINVAL;
        return (-1);
    }
    srclen = strnlen (src, dstlen);
    if (srclen >= dstlen) {
        errno = ENAMETOOLONG;
        return (-1);
    }
    memcpy (dst, src, srclen + 1);

    for (p = dst + srclen - 1; p >= dst; p--) {
        if (state == start) {
            state = (*p == '/') ? last_slash : last_word;
        }
        else if (state == last_slash) {
            if (*p != '/') state = last_word;
        }
        else if (state == last_word) {
            if (*p == '/') state = prev_slash;
        }
        else if (state == prev_slash) {
            if (*p != '/') break;
        }
        *p = '\0';
    }
    if (p < dst) {
        dst[0] = (state == prev_slash || state == last_slash) ? '/' : '.';
        dst[1] = '\0';
    }
    return (0);
}


/*  Checks if the specified [path] is accessible by all users.
 *  Returns 1 if all checks pass, 0 if any checks fail, or -1 on error
 *    (with errno set).
 *  If [errbuf] is non-NULL, a message describing the inaccessibility or error
 *    will be written to the buffer [errbuf] of length [errbuflen].
 */
int
path_is_accessible (const char *path, char *errbuf, size_t errbuflen)
{
    int          n;
    char         buf [PATH_MAX];
    struct stat  st;
    char        *p;

    n = path_canonicalize (path, buf, sizeof (buf));
    if (n < 0) {
        return (_path_set_err (-1, errbuf, errbuflen,
            "cannot canonicalize \"%s\": %s", path, strerror (errno)));
    }
    if (lstat (buf, &st) < 0) {
        return (_path_set_err (-1, errbuf, errbuflen,
            "cannot stat \"%s\": %s", buf, strerror (errno)));
    }
    if (!S_ISDIR (st.st_mode)) {
        if ((p = strrchr (buf, '/'))) {
            *p = '\0';
        }
    }
    while (buf[0] != '\0') {
        if (lstat (buf, &st) < 0) {
            return (_path_set_err (-1, errbuf, errbuflen,
                "cannot stat \"%s\": %s", buf, strerror (errno)));
        }
        if (!S_ISDIR (st.st_mode)) {
            errno = EINVAL;
            return (_path_set_err (-1, errbuf, errbuflen,
                "cannot check \"%s\": unexpected file type (st_mode=0%o)",
                buf, st.st_mode));
        }
        if ((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
                != (S_IXUSR | S_IXGRP | S_IXOTH)) {
            return (_path_set_err (0, errbuf, errbuflen,
                "execute permissions for all required on \"%s\" (st_mode=0%o)",
                buf, st.st_mode));
        }
        if (!(p = strrchr (buf, '/'))) {
            errno = EINVAL;
            return (_path_set_err (-1, errbuf, errbuflen,
                "cannot check \"%s\": internal error", buf));
        }
        if ((p == buf) && (buf[1] != '\0')) {
            p++;
        }
        *p = '\0';
    }
    return (1);
}


/*  Checks if the specified [path] is secure, ensuring that the base directory
 *    cannot be modified by anyone other than the current user, the trusted
 *    group (if set), or root.
 *  Returns 1 if all checks pass, 0 if any checks fail, or -1 on error
 *    (with errno set).
 *  If [errbuf] is non-NULL, a message describing the insecurity or error
 *    will be written to the buffer [errbuf] of length [errbuflen].
 */
int
path_is_secure (const char *path, char *errbuf, size_t errbuflen,
                path_security_flag_t flags)
{
    int          n;
    char         buf [PATH_MAX];
    struct stat  st;
    char        *p;
    uid_t        euid;

    n = path_canonicalize (path, buf, sizeof (buf));
    if (n < 0) {
        return (_path_set_err (-1, errbuf, errbuflen,
            "cannot canonicalize \"%s\": %s", path, strerror (errno)));
    }
    if (lstat (buf, &st) < 0) {
        return (_path_set_err (-1, errbuf, errbuflen,
            "cannot stat \"%s\": %s", buf, strerror (errno)));
    }
    if (!S_ISDIR (st.st_mode)) {
        if ((p = strrchr (buf, '/'))) {
            *p = '\0';
        }
    }
    euid = geteuid ();

    while (buf[0] != '\0') {
        if (lstat (buf, &st) < 0) {
            return (_path_set_err (-1, errbuf, errbuflen,
                "cannot stat \"%s\": %s", buf, strerror (errno)));
        }
        if (!S_ISDIR (st.st_mode)) {
            errno = EINVAL;
            return (_path_set_err (-1, errbuf, errbuflen,
                "cannot check \"%s\": unexpected file type (st_mode=0%o)",
                buf, st.st_mode));
        }
        if ((st.st_uid != 0) && (st.st_uid != euid)) {
            return (_path_set_err (0, errbuf, errbuflen,
                "invalid ownership of \"%s\" (uid=%lu)",
                buf, (unsigned long) st.st_uid));
        }
        if (!(flags & PATH_SECURITY_IGNORE_GROUP_WRITE) &&
             (st.st_mode & S_IWGRP)                     &&
            !(st.st_mode & S_ISVTX)                     &&
             ((st.st_gid != _path_trusted_gid) ||
              (_path_trusted_gid == GID_SENTINEL))) {
            return (_path_set_err (0, errbuf, errbuflen,
                "group-writable permissions without sticky bit set on \"%s\"",
                buf));
        }
        if ((st.st_mode & S_IWOTH) && !(st.st_mode & S_ISVTX)) {
            return (_path_set_err (0, errbuf, errbuflen,
                "world-writable permissions without sticky bit set on \"%s\"",
                buf));
        }
        if (!(p = strrchr (buf, '/'))) {
            errno = EINVAL;
            return (_path_set_err (-1, errbuf, errbuflen,
                "cannot check \"%s\": internal error", buf));
        }
        if ((p == buf) && (buf[1] != '\0')) {
            p++;
        }
        *p = '\0';
    }
    return (1);
}


/*  Gets the "trusted group" for permission checks on a directory hierarchy,
 *    storing the GID at [gid_ptr].
 *  Returns 0 on success with the "trusted group" GID stored at [gid_ptr]
 *    (if non-NULL).  Returns -1 on error without updating [gid_ptr].
 *  Warning: Not thread-safe.
 */
int
path_get_trusted_group (gid_t *gid_ptr)
{
    if (_path_trusted_gid == GID_SENTINEL) {
        errno = ERANGE;
        return (-1);
    }
    if (gid_ptr != NULL) {
        *gid_ptr = _path_trusted_gid;
    }
    return (0);
}


/*  Sets the "trusted group" for permission checks on a directory hierarchy.
 *    Directories with write permissions for group are allowed if they are
 *    owned by the trusted group.
 *  The [group] string can specify either a group name or GID.
 *    If [group] is NULL, the trusted group setting is cleared.
 *  Returns 0 on success, or -1 on error.
 *  Warning: Not thread-safe.
 */
int
path_set_trusted_group (const char *group)
{
    if (group == NULL) {
        _path_trusted_gid = GID_SENTINEL;
        return (0);
    }
    return (query_gid (group, &_path_trusted_gid));
}


/*****************************************************************************
 *  Internal Functions
 *****************************************************************************/

static int
_path_set_err (int rc, char *buf, size_t buflen, const char *format, ...)
{
/*  Sets an error condition to be returned to the caller.
 *  If [buf] is non-NULL, the [format] string will be expanded and written
 *    to the buffer [buf] of length [buflen].
 *  Returns [rc].
 */
    va_list vargs;

    if ((buf != NULL) && (buflen > 0)) {
        va_start (vargs, format);
        (void) vsnprintf (buf, buflen, format, vargs);
        buf [buflen - 1] = '\0';
        va_end (vargs);
    }
    return (rc);
}
