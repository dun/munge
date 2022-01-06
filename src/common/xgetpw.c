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

#if   HAVE_GETPWNAM_R_POSIX
#define _POSIX_PTHREAD_SEMANTICS 1      /* for SunOS */
#elif HAVE_GETPWNAM_R_AIX
#define _THREAD_SAFE 1
#define _UNIX95 1
#define _XOPEN_SOURCE_EXTENDED 1
#elif HAVE_GETPWNAM_R_SUN
#undef _POSIX_PTHREAD_SEMANTICS
#elif HAVE_GETPWNAM
#ifdef WITH_PTHREADS
#include <pthread.h>
#endif /* WITH_PTHREADS */
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
#include "xgetpw.h"


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

#define MINIMUM_PW_BUF_SIZE     1024


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

static size_t _xgetpwbuf_get_sys_size (void);

static int _xgetpwbuf_grow (xpwbuf_p pwbufp, size_t minlen);

static int _xgetpwbuf_copy_struct (const struct passwd *src,
    struct passwd *dst, xpwbuf_p pwbufp) _UNUSED_;

static int _xgetpwbuf_copy_string (const char *src, char **dstp,
    char **bufp, size_t *buflenp) _UNUSED_;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

xpwbuf_p
xgetpwbuf_create (size_t len)
{
/*  Allocates a buffer for xgetpwnam().  [len] specifies a suggested size
 *    for the buffer; if 0, the system recommended size will be used.
 *  Returns the buffer on success, or NULL on error (with errno).
 */
    xpwbuf_p pwbufp;

    if (len == 0) {
        len = _xgetpwbuf_get_sys_size ();
    }
    pwbufp = malloc (sizeof (struct xpwbuf_t));
    if (pwbufp == NULL) {
        return (NULL);
    }
    pwbufp->buf = malloc (len);
    if (pwbufp->buf == NULL) {
        free (pwbufp);
        return (NULL);
    }
    pwbufp->len = len;
    log_msg (LOG_DEBUG, "Created password entry buffer of size %u", len);
    return (pwbufp);
}


void
xgetpwbuf_destroy (xpwbuf_p pwbufp)
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


size_t
xgetpwbuf_get_len (xpwbuf_p pwbufp)
{
/*  Returns the current size of the allocated buffer within [pwbufp],
 *    or 0 on error (with errno).
 */
    if (pwbufp == NULL) {
        errno = EINVAL;
        return (0);
    }
    return (pwbufp->len);
}


int
xgetpwnam (const char *name, struct passwd *pwp, xpwbuf_p pwbufp)
{
/*  Portable encapsulation of getpwnam_r().
 *  Queries the password database for [name], storing the struct passwd result
 *    in [pwp] and additional strings in the buffer [pwbufp].
 *  Returns 0 on success, or -1 on error (with errno).
 *    Returns -1 with ENOENT when [name] is not found.
 */
#if   HAVE_GETPWNAM_R_POSIX
    struct passwd          *rv_pwp;
#elif HAVE_GETPWNAM_R_AIX
#elif HAVE_GETPWNAM_R_SUN
    struct passwd          *rv_pwp;
#elif HAVE_GETPWNAM
#ifdef WITH_PTHREADS
    static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
    int                     rv_mutex;
#endif /* WITH_PTHREADS */
    int                     rv_copy;
    struct passwd          *rv_pwp;
#endif /* HAVE_GETPWNAM */
    int                     rv;
    int                     got_err;
    int                     got_none;

    if ((name == NULL)    ||
        (name[0] == '\0') ||
        (pwp == NULL)     ||
        (pwbufp == NULL))
    {
        errno = EINVAL;
        return (-1);
    }
    assert (pwbufp->buf != NULL);
    assert (pwbufp->len > 0);

restart:
    errno = 0;
    got_err = 0;
    got_none = 0;

#if   HAVE_GETPWNAM_R_POSIX
    rv_pwp = NULL;
    rv = getpwnam_r (name, pwp, pwbufp->buf, pwbufp->len, &rv_pwp);
    /*
     *  POSIX.1-2001 does not call "name not found" an error, so the return
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
        /*  Likely that the name was not found.
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
        /*  Unable to distinguish "name not found" from error.
         */
        else {
            got_none = 1;
        }
    }
#elif HAVE_GETPWNAM_R_AIX
    rv = getpwnam_r (name, pwp, pwbufp->buf, pwbufp->len);
    if (rv != 0) {
        if (errno == ESRCH) {
            got_none = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETPWNAM_R_SUN
    rv_pwp = getpwnam_r (name, pwp, pwbufp->buf, pwbufp->len);
    if (rv_pwp == NULL) {
        if (errno == 0) {
            got_none = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETPWNAM
#ifdef WITH_PTHREADS
    if ((rv_mutex = pthread_mutex_lock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock xgetpwnam mutex");
    }
#endif /* WITH_PTHREADS */
    rv_pwp = getpwnam (name);
    /*
     *  The initial test for (errno != 0), while redundant, allows for the
     *    "name not found" case to short-circuit the rest of the if-condition
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
        rv_copy = 0;
    }
    else {
        rv_copy = _xgetpwbuf_copy_struct (rv_pwp, pwp, pwbufp);
    }
#ifdef WITH_PTHREADS
    if ((rv_mutex = pthread_mutex_unlock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock xgetpwnam mutex");
    }
#endif /* WITH_PTHREADS */
    if (rv_copy < 0) {
        return (-1);
    }
#endif /* HAVE_GETPWNAM */

    if (got_none) {
        errno = ENOENT;
        return (-1);
    }
    if (got_err) {
        if (errno == EINTR) {
            goto restart;
        }
        if (errno == ERANGE) {
            rv = _xgetpwbuf_grow (pwbufp, 0);
            if (rv == 0) {
                goto restart;
            }
        }
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
_xgetpwbuf_get_sys_size (void)
{
/*  Returns the system recommended size for the xgetpw buffer.
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
_xgetpwbuf_grow (xpwbuf_p pwbufp, size_t minlen)
{
/*  Grows the buffer [pwbufp] to be at least as large as the length [minlen].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    size_t  newlen;
    char   *newbuf;

    assert (pwbufp != NULL);
    assert (pwbufp->buf != NULL);
    assert (pwbufp->len > 0);

    newlen = pwbufp->len;
    do {
        newlen *= 2;
        if (newlen < pwbufp->len) {     /* newlen overflowed */
            errno = ENOMEM;
            return (-1);
        }
    } while (newlen < minlen);

    newbuf = realloc (pwbufp->buf, newlen);
    if (newbuf == NULL) {
        errno = ENOMEM;
        return (-1);
    }
    pwbufp->buf = newbuf;
    pwbufp->len = newlen;

    log_msg (LOG_INFO, "Increased password entry buffer size to %u", newlen);
    return (0);
}


static int
_xgetpwbuf_copy_struct (const struct passwd *src, struct passwd *dst,
                        xpwbuf_p pwbufp)
{
/*  Copies the struct passwd [src] into [dst], placing additional strings
 *    and whatnot into buffer [pwbuf].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    size_t  num_bytes;
    char   *p;

    assert (src != NULL);
    assert (dst != NULL);
    assert (pwbufp != NULL);
    assert (pwbufp->buf != NULL);
    assert (pwbufp->len > 0);

    /*  Compute requisite buffer space.
     */
    num_bytes = 0;
    if (src->pw_name) {
        num_bytes += strlen (src->pw_name) + 1;
    }
    if (src->pw_passwd) {
        num_bytes += strlen (src->pw_passwd) + 1;
    }
    if (src->pw_gecos) {
        num_bytes += strlen (src->pw_gecos) + 1;
    }
    if (src->pw_dir) {
        num_bytes += strlen (src->pw_dir) + 1;
    }
    if (src->pw_shell) {
        num_bytes += strlen (src->pw_shell) + 1;
    }
    /*  Ensure requisite buffer space.
     */
    if (pwbufp->len < num_bytes) {
        if (_xgetpwbuf_grow (pwbufp, num_bytes) < 0) {
            return (-1);
        }
    }
    /*  Copy password entry.
     */
    assert (pwbufp->len >= num_bytes);
    memset (dst, 0, sizeof (*dst));
    p = pwbufp->buf;

    if (_xgetpwbuf_copy_string
            (src->pw_name, &(dst->pw_name), &p, &num_bytes) < 0) {
        goto err;
    }
    if (_xgetpwbuf_copy_string
            (src->pw_passwd, &(dst->pw_passwd), &p, &num_bytes) < 0) {
        goto err;
    }
    if (_xgetpwbuf_copy_string
            (src->pw_gecos, &(dst->pw_gecos), &p, &num_bytes) < 0) {
        goto err;
    }
    if (_xgetpwbuf_copy_string
            (src->pw_dir, &(dst->pw_dir), &p, &num_bytes) < 0) {
        goto err;
    }
    if (_xgetpwbuf_copy_string
            (src->pw_shell, &(dst->pw_shell), &p, &num_bytes) < 0) {
        goto err;
    }
    dst->pw_uid = src->pw_uid;
    dst->pw_gid = src->pw_gid;

    assert (p <= pwbufp->buf + pwbufp->len);
    return (0);

err:
    errno = ERANGE;
    return (-1);
}


static int
_xgetpwbuf_copy_string (const char *src, char **dstp,
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
