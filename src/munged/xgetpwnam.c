/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2012 Lawrence Livermore National Security, LLC.
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <munge.h>
#include "log.h"
#include "xgetpwnam.h"


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

#define MINIMUM_PW_BUF_SIZE     4096


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct xpwbuf_t {
    char   *buf;
    size_t  len;
};


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static size_t _xgetpwnam_buf_get_sys_size (void);

static int _xgetpwnam_copy (const struct passwd *src, struct passwd *dst,
    char *buf, size_t buflen) _UNUSED_;

static int _xgetpwnam_copy_str (const char *src, char **dstp,
    char **bufp, size_t *buflenp) _UNUSED_;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

xpwbuf_p
xgetpwnam_buf_create (void)
{
/*  Allocates a buffer for xgetpwnam().
 *  Returns the buffer on success, or NULL on error (with errno).
 */
    static int pw_buf_size = -1;
    xpwbuf_p   pwbufp;

    if (pw_buf_size < 0) {
        pw_buf_size = _xgetpwnam_buf_get_sys_size ();
    }
    if (!(pwbufp = malloc (sizeof (struct xpwbuf_t)))) {
        return (NULL);
    }
    if (!(pwbufp->buf = malloc (pw_buf_size))) {
        free (pwbufp);
        return (NULL);
    }
    pwbufp->len = pw_buf_size;
    return (pwbufp);
}


void
xgetpwnam_buf_destroy (xpwbuf_p pwbufp)
{
/*  Destroys the buffer [pwbufp].
 */
    if (pwbufp != NULL) {
        if (pwbufp->buf != NULL) {
            free (pwbufp->buf);
        }
        free (pwbufp);
    }
    return;
}


int
xgetpwnam (const char *user, struct passwd *pwp, xpwbuf_p pwbufp)
{
/*  Portable encapsulation of getpwnam_r().
 *  Queries the password database for [user], storing the struct passwd result
 *    in [pwp] and additional strings in the buffer [pwbufp].
 *  Returns 0 on success, or -1 on error (with errno).
 *    Returns -1 with ENOENT when [user] is not found.
 */
#if   HAVE_GETPWNAM_R_POSIX
    int                     rv;
    struct passwd          *rv_pwp;
#elif HAVE_GETPWNAM_R_AIX
    int                     rv;
#elif HAVE_GETPWNAM_R_SUN
    struct passwd          *rv_pwp;
#elif HAVE_GETPWNAM
    static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
    int                     rv_mutex;
    int                     rv_copy;
    struct passwd          *rv_pwp;
#endif
    int                     got_err = 0;
    int                     got_none = 0;

    if ((user == NULL)    ||
        (user[0] == '\0') ||
        (pwp == NULL)     ||
        (pwbufp == NULL))
    {
        errno = EINVAL;
        return (-1);
    }
    assert (pwbufp->buf != NULL);
    assert (pwbufp->len > 0);

    errno = 0;

#if   HAVE_GETPWNAM_R_POSIX
    rv = getpwnam_r (user, pwp, pwbufp->buf, pwbufp->len, &rv_pwp);
    /*
     *  POSIX.1-2001 does not call "user not found" an error, so the return
     *    value of getpwnam_r() is of limited value.  When errors do occur,
     *    some systems return them via the retval, some via errno, and some
     *    return no indication whatsoever.
     */
    if (rv_pwp == NULL) {
        /*
         *  Coalesce the error number onto rv if needed.
         */
        if ((rv < 0) && (errno != 0)) {
            rv = errno;
        }
        /*  Likely that the user was not found.
         */
        if ((rv == 0)      ||
            (rv == ENOENT) ||
            (rv == ESRCH))
        {
            got_none = 1;
        }
        /*  Likely that an error occurred.
         */
        else if (
            (rv == EINTR)  ||
            (rv == ERANGE) ||
            (rv == EIO)    ||
            (rv == EMFILE) ||
            (rv == ENFILE))
        {
            got_err = 1;
            errno = rv;
        }
        /*  Unable to distinguish "user not found" from error.
         */
        else {
            got_none = 1;
        }
    }
#elif HAVE_GETPWNAM_R_AIX
    rv = getpwnam_r (user, pwp, pwbufp->buf, pwbufp->len);
    if (rv != 0) {
        if (errno == ESRCH) {
            got_none = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETPWNAM_R_SUN
    rv_pwp = getpwnam_r (user, pwp, pwbufp->buf, pwbufp->len);
    if (rv_pwp == NULL) {
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
    rv_pwp = getpwnam (user);
    /*
     *  The initial test for (errno != 0), while redundant, allows for the
     *    "user not found" case to short-circuit the rest of the if-condition
     *    on many systems.
     */
    if (rv_pwp == NULL) {
        if ((errno != 0) &&
            ((errno == EINTR)  ||
             (errno == ERANGE) ||
             (errno == EIO)    ||
             (errno == EMFILE) ||
             (errno == ENFILE) ||
             (errno == ENOMEM)))
        {
            got_err = 1;
        }
        else {
            got_none = 1;
        }
    }
    else {
        rv_copy = _xgetpwnam_copy (rv_pwp, pwp, pwbufp->buf, pwbufp->len);
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
    /*  Some systems set errno even on success.  Go figure.
     */
    errno = 0;
    return (0);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static size_t
_xgetpwnam_buf_get_sys_size (void)
{
/*  Returns the system recommended size for the xgetpwnam() buffer.
 */
    long   n = -1;
    size_t len;

#if HAVE_SYSCONF
#ifdef _SC_GETPW_R_SIZE_MAX
    n = sysconf (_SC_GETPW_R_SIZE_MAX);
#endif /* _SC_GETPW_R_SIZE_MAX */
#endif /* HAVE_SYSCONF */

    len = (n <= MINIMUM_PW_BUF_SIZE) ? MINIMUM_PW_BUF_SIZE : (size_t) n;
    return (len);
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
_xgetpwnam_copy_str (const char *src, char **dstp,
                     char **bufp, size_t *buflenp)
{
/*  Copies the string [src] into the buffer [bufp] of size [buflenp],
 *    setting the pointer [dstp] to the newly-copied string.  The values
 *    for [bufp] and [buflenp] are adjusted for the remaining buffer space.
 *  Note that [dstp], [bufp], and [buflenp] are all passed by reference.
 *  Returns the number of bytes copied, or -1 on error.
 */
    size_t n;

    assert (dstp != NULL);
    assert (bufp != NULL);
    assert (*bufp != NULL);
    assert (buflenp != NULL);

    if (src == NULL) {
        *dstp = NULL;
        return (0);
    }
    n = strlen (src) + 1;
    if (*buflenp < n) {
        return (-1);
    }
    *dstp = strcpy (*bufp, src);
    *bufp += n;
    *buflenp -= n;
    return (n);
}
