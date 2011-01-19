/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://munge.googlecode.com/>.
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

#if   HAVE_GETPWNAM_R_POSIX
#define _POSIX_PTHREAD_SEMANTICS 1      /* for SunOS */
#elif HAVE_GETPWNAM_R_AIX
#define _THREAD_SAFE 1
#define _UNIX95 1
#define _XOPEN_SOURCE_EXTENDED 1
#elif HAVE_GETPWNAM_R_SUN
#undef _POSIX_PTHREAD_SEMANTICS
#elif HAVE_GETPWNAM
#include <pthread.h>
#else
#error "getpwnam() not supported"
#endif

#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <munge.h>
#include "log.h"


/*****************************************************************************
 *  Compiler Fu
 *****************************************************************************/

#ifdef __GNUC__
#define _UNUSED_ __attribute__ ((unused))
#else
#define _UNUSED_
#endif


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define DEFAULT_PW_BUF_SIZE     4096


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static int _xgetpwnam_get_buf_size (void);

static int _xgetpwnam_copy (const struct passwd *src, struct passwd *dst,
    char *buf, size_t buflen) _UNUSED_;

static int _xgetpwnam_copy_str (const char *src, char **dst_p,
    char **buf_p, size_t *buflen_p) _UNUSED_;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

int
xgetpwnam_buf_create (char **buf_p, int *buflen_p)
{
/*  Allocates a buffer for xgetpwnam(), storing the result in [buf_p];
 *    the size of the buffer is returned in [buflen_p].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    static int  pw_buf_size = -1;
    char       *buf;

    if ((buf_p == NULL) || (buflen_p == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    if (pw_buf_size < 0) {
        pw_buf_size = _xgetpwnam_get_buf_size ();
    }
    buf = malloc (pw_buf_size);
    if (buf == NULL) {
        return (-1);
    }
    *buf_p = buf;
    *buflen_p = pw_buf_size;
    return (0);
}


void
xgetpwnam_buf_destroy (char *buf)
{
/*  Destroys the buffer [buf].
 */
    if (buf != NULL) {
        free (buf);
    }
    return;
}


int
xgetpwnam (const char *user, struct passwd *pw, char *buf, size_t buflen)
{
/*  Portable encapsulation of getpwnam_r().
 *  Queries the password database for [user], storing the struct passwd result
 *    in [pw] and additional strings in buffer [buf] of length [buflen].
 *  Returns 0 on success, or -1 on error (with errno).
 *    Returns -1 with ENOENT when [user] is not found.
 */
#if   HAVE_GETPWNAM_R_POSIX
    int                     rv;
    struct passwd          *pw_ptr;
#elif HAVE_GETPWNAM_R_AIX
    int                     rv;
#elif HAVE_GETPWNAM_R_SUN
    struct passwd          *pw_ptr;
#elif HAVE_GETPWNAM
    static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
    int                     rv_mutex;
    int                     rv_copy;
    struct passwd          *pw_ptr;
#endif
    int                     got_err = 0;
    int                     got_none = 0;

    if ((user == NULL) || (*user == '\0') || (pw == NULL)
            || (buf == NULL) || (buflen <= 0)) {
        errno = EINVAL;
        return (-1);
    }
    errno = 0;

#if   HAVE_GETPWNAM_R_POSIX
    rv = getpwnam_r (user, pw, buf, buflen, &pw_ptr);
    /*
     *  POSIX.1-2001 does not call "user not found" an error, so the
     *    return value of getpwnam_r() is of limited value.  For example,
     *    "user not found" can be returned in the following ways:
     *    - Linux and SunOS: rv=0 and errno=0
     *    - OpenBSD: rv=1 and errno=EACCESS
     *    - AIX: rv=-1 and errno=ESRCH
     *  Strangely, the list of known errors is better defined; so these errors
     *    are tested for, and anything else is assumed to be "user not found".
     */
    if (pw_ptr == NULL) {
        if ((rv != 0)
            &&   ( (errno == EINTR)
                || (errno == EIO)
                || (errno == EMFILE)
                || (errno == ENFILE)
                || (errno == ENOMEM)
                || (errno == ERANGE) )) {
            got_err = 1;
        }
        else {
            got_none = 1;
        }
    }
#elif HAVE_GETPWNAM_R_AIX
    rv = getpwnam_r (user, pw, buf, buflen);
    if (rv != 0) {
        if (errno == ESRCH) {
            got_none = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETPWNAM_R_SUN
    pw_ptr = getpwnam_r (user, pw, buf, buflen);
    if (pw_ptr == NULL) {
        if (errno == 0) {
            got_none = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETPWNAM
    if ((rv_mutex = pthread_mutex_lock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock xgetpwnam mutex");
    }
    pw_ptr = getpwnam (user);
    /*
     *  Refer to the HAVE_GETPWNAM_R_POSIX case regarding the "user not found"
     *    return value conundrum.
     *  The initial test for (errno != 0), while redundant, allows for the
     *    "user not found" case to short-circuit the rest of the if-condition
     *    on Linux / SunOS / Darwin.
     */
    if (pw_ptr == NULL) {
        if ((errno != 0)
            &&   ( (errno == EINTR)
                || (errno == EIO)
                || (errno == EMFILE)
                || (errno == ENFILE)
                || (errno == ENOMEM)
                || (errno == ERANGE) )) {
            got_err = 1;
        }
        else {
            got_none = 1;
        }
    }
    else {
        rv_copy = _xgetpwnam_copy (pw_ptr, pw, buf, buflen);
    }
    if ((rv_mutex = pthread_mutex_unlock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock xgetpwnam mutex");
    }
    if (rv_copy < 0) {
        return (-1);
    }
#endif

    if (got_none) {
        errno = ENOENT;
        return (-1);
    }
    if (got_err) {
        return (-1);
    }
    return (0);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static int
_xgetpwnam_get_buf_size (void)
{
/*  Returns the recommended size of the getpwnam_r() caller-provided buffer.
 */
    static int n = -1;

    if (n < 0) {

#if HAVE_SYSCONF
#ifdef _SC_GETPW_R_SIZE_MAX
        n = sysconf (_SC_GETPW_R_SIZE_MAX);
#endif /* _SC_GETPW_R_SIZE_MAX */
#endif /* HAVE_SYSCONF */

        if (n <= 0) {
            n = DEFAULT_PW_BUF_SIZE;
        }
        log_msg (LOG_DEBUG, "Using pw buf size of %d", n);
    }
    return (n);
}


static int
_xgetpwnam_copy (const struct passwd *src, struct passwd *dst,
                 char *buf, size_t buflen)
{
/*  Copies the passwd entry [src] into [dst], placing additional strings
 *    and whatnot into buffer [buf] of length [buflen].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    char   *p = buf;
    size_t  nleft = buflen;

    assert (src != NULL);
    assert (dst != NULL);
    assert (buf != NULL);
    assert (buflen > 0);

    if (_xgetpwnam_copy_str
            (src->pw_name, &(dst->pw_name), &p, &nleft) < 0) {
        goto err;
    }
    if (_xgetpwnam_copy_str
            (src->pw_passwd, &(dst->pw_passwd), &p, &nleft) < 0) {
        goto err;
    }
    if (_xgetpwnam_copy_str
            (src->pw_gecos, &(dst->pw_gecos), &p, &nleft) < 0) {
        goto err;
    }
    if (_xgetpwnam_copy_str
            (src->pw_dir, &(dst->pw_dir), &p, &nleft) < 0) {
        goto err;
    }
    if (_xgetpwnam_copy_str
            (src->pw_shell, &(dst->pw_shell), &p, &nleft) < 0) {
        goto err;
    }
    dst->pw_uid = src->pw_uid;
    dst->pw_gid = src->pw_gid;

    assert (p <= buf + buflen);
    return (0);

err:
    errno = ERANGE;
    return (-1);
}


static int
_xgetpwnam_copy_str (const char *src, char **dst_p,
                     char **buf_p, size_t *buflen_p)
{
/*  Copies the string [src] into the buffer [*buf_p] of size [*buflen_p],
 *    setting the pointer [*dst_p] to the newly-copied string.  The values
 *    for [buf_p] and [buflen_p] are adjusted for the remaining buffer space.
 *  Note that [dst_p], [buf_p], and [buflen_p] are all passed by reference.
 *  Returns the number of bytes copied, or -1 on error.
 */
    size_t n;

    assert (dst_p != NULL);
    assert (buf_p != NULL);
    assert (*buf_p != NULL);
    assert (buflen_p != NULL);

    if (src == NULL) {
        *dst_p = NULL;
        return (0);
    }
    n = strlen (src) + 1;
    if (*buflen_p < n) {
        return (-1);
    }
    (void) strcpy (*buf_p, src);
    *dst_p = *buf_p;
    *buf_p += n;
    *buflen_p -= n;
    return (n);
}
