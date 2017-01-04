/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2017 Lawrence Livermore National Security, LLC.
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

#if   HAVE_GETGRENT_R_GNU
#define _GNU_SOURCE 1
#elif HAVE_GETGRENT_R_AIX
#define HAVE_GETGRENT_R_ERANGE_BROKEN 1
#define _THREAD_SAFE 1
#include <stdio.h>
#elif HAVE_GETGRENT_R_SUN
#define HAVE_GETGRENT_R_ERANGE_BROKEN 1
#elif HAVE_GETGRENT
#include <pthread.h>
#else
#error "getgrent() not supported"
#endif

#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <munge.h>
#include "log.h"
#include "xgetgrent.h"


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

#define MINIMUM_GR_BUF_SIZE     1024


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct xgrbuf_t {
    char   *buf;
    size_t  len;
};


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

#if HAVE_GETGRENT_R_AIX
static FILE *_gr_fp;
#endif


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static size_t _xgetgrent_buf_get_sys_size (void);

static int _xgetgrent_buf_grow (xgrbuf_p grbufp, size_t minlen);

static int _xgetgrent_copy (const struct group *src, struct group *dst,
    xgrbuf_p grbufp) _UNUSED_;

static int _xgetgrent_copy_str (const char *src, char **dstp,
    char **bufp, size_t *buflenp) _UNUSED_;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

xgrbuf_p
xgetgrent_buf_create (size_t len)
{
/*  Allocates a buffer for xgetgrent().  [len] specifies a suggested size
 *    for the buffer; if 0, the system recommended size will be used.
 *  Returns the buffer on success, or NULL on error (with errno).
 */
    xgrbuf_p grbufp;

    if (len == 0) {
        len = _xgetgrent_buf_get_sys_size ();
    }
    grbufp = malloc (sizeof (struct xgrbuf_t));
    if (grbufp == NULL) {
        return (NULL);
    }
    grbufp->buf = malloc (len);
    if (grbufp->buf == NULL) {
        free (grbufp);
        return (NULL);
    }
    grbufp->len = len;
    log_msg (LOG_DEBUG, "Created group entry buffer of size %u", len);
    return (grbufp);
}


void
xgetgrent_buf_destroy (xgrbuf_p grbufp)
{
/*  Destroys the buffer [grbufp].
 */
    if (grbufp != NULL) {
        if (grbufp->buf != NULL) {
            free (grbufp->buf);
        }
        free (grbufp);
    }
    return;
}


size_t
xgetgrent_buf_get_len (xgrbuf_p grbufp)
{
/*  Returns the current size of the allocated buffer within [grbufp],
 *    or 0 on error (with errno).
 */
    if (grbufp == NULL) {
        errno = EINVAL;
        return (0);
    }
    return (grbufp->len);
}


void
xgetgrent_init (void)
{
/*  Portable encapsulation of setgrent().
 */
#if HAVE_GETGRENT_R_AIX
    _gr_fp = NULL;
#endif
    setgrent ();
    return;
}


int
xgetgrent (struct group *grp, xgrbuf_p grbufp)
{
/*  Portable encapsulation of getgrent_r().
 *  Reads the next group entry from the stream initialized by xgetgrent_init(),
 *    storing the struct group result in [grp] and additional strings in the
 *    buffer [grbufp].
 *  Returns 0 on success, or -1 on error (with errno).
 *  Returns -1 with ENOENT when there are no more entries.
 *  Returns -1 with ERANGE when the underlying getgrent_r() call cannot be
 *    automatically restarted after resizing the buffer [grbufp].
 */
    int                     rv;
#if   HAVE_GETGRENT_R_GNU
    struct group           *rv_grp;
#elif HAVE_GETGRENT_R_AIX
#elif HAVE_GETGRENT_R_SUN
    struct group           *rv_grp;
#elif HAVE_GETGRENT
    static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
    int                     rv_mutex;
    int                     rv_copy;
    struct group           *rv_grp;
#endif
    int                     got_eof;
    int                     got_err;

    if ((grp == NULL) || (grbufp == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    assert (grbufp->buf != NULL);
    assert (grbufp->len > 0);

restart:
    errno = 0;
    got_eof = 0;
    got_err = 0;

#if   HAVE_GETGRENT_R_GNU
    rv = getgrent_r (grp, grbufp->buf, grbufp->len, &rv_grp);
    if (((rv == ENOENT) || (rv == 0)) && (rv_grp == NULL)) {
        got_eof = 1;
    }
    else if (rv != 0) {
        got_err = 1;
        errno = rv;
    }
#elif HAVE_GETGRENT_R_AIX
    rv = getgrent_r (grp, grbufp->buf, grbufp->len, &_gr_fp);
    if (rv != 0) {
        if (errno == 0) {
            got_eof = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETGRENT_R_SUN
    rv_grp = getgrent_r (grp, grbufp->buf, grbufp->len);
    if (rv_grp == NULL) {
        if (errno == 0) {
            got_eof = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETGRENT
    if ((rv_mutex = pthread_mutex_lock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock xgetgrent mutex");
    }
    rv_grp = getgrent ();
    if (rv_grp == NULL) {
        if ((errno == 0) || (errno == ENOENT)) {
            got_eof = 1;
        }
        else {
            got_err = 1;
        }
    }
    else {
        rv_copy = _xgetgrent_copy (rv_grp, grp, grbufp);
    }
    if ((rv_mutex = pthread_mutex_unlock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock xgetgrent mutex");
    }
    if (rv_copy < 0) {
        return (-1);
    }
#endif

    if (got_eof) {
        errno = ENOENT;
        return (-1);
    }
    if (got_err) {
        if (errno == ERANGE) {
            rv = _xgetgrent_buf_grow (grbufp, 0);
#if ! HAVE_GETGRENT_R_ERANGE_BROKEN
            if (rv == 0) {
                goto restart;
            }
#endif /* ! HAVE_GETGRENT_R_ERANGE_BROKEN */
        }
        return (-1);
    }
    return (0);
}


void
xgetgrent_fini (void)
{
/*  Portable encapsulation of endgrent().
 */
    endgrent ();
    return;
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static size_t
_xgetgrent_buf_get_sys_size (void)
{
/*  Returns the system recommended size for the xgetgrent() buffer.
 */
    long   n = -1;
    size_t len;

#if HAVE_SYSCONF
#ifdef _SC_GETGR_R_SIZE_MAX
    n = sysconf (_SC_GETGR_R_SIZE_MAX);
#endif /* _SC_GETGR_R_SIZE_MAX */
#endif /* HAVE_SYSCONF */

    len = (n <= MINIMUM_GR_BUF_SIZE) ? MINIMUM_GR_BUF_SIZE : (size_t) n;
    return (len);
}


static int
_xgetgrent_buf_grow (xgrbuf_p grbufp, size_t minlen)
{
/*  Grows the buffer [grbufp] to be at least as large as the length [minlen].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    size_t  newlen;
    char   *newbuf;

    assert (grbufp != NULL);
    assert (grbufp->buf != NULL);
    assert (grbufp->len > 0);

    newlen = grbufp->len;
    do {
        newlen *= 2;
        if (newlen < grbufp->len) {     /* newlen overflowed */
            errno = ENOMEM;
            return (-1);
        }
    } while (newlen < minlen);

    newbuf = realloc (grbufp->buf, newlen);
    if (newbuf == NULL) {
        errno = ENOMEM;
        return (-1);
    }
    grbufp->buf = newbuf;
    grbufp->len = newlen;

    log_msg (LOG_INFO, "Increased group entry buffer size to %u", newlen);
    return (0);
}


static int
_xgetgrent_copy (const struct group *src, struct group *dst, xgrbuf_p grbufp)
{
/*  Copies the group entry [src] into [dst], placing additional strings and
 *    whatnot into the buffer [grbufp].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    int      num_ptrs;
    size_t   num_bytes;
    char   **userp;
    char    *p;
    size_t   n;
    int      i;

    assert (src != NULL);
    assert (dst != NULL);
    assert (grbufp != NULL);
    assert (grbufp->buf != NULL);
    assert (grbufp->len > 0);

    /*  Compute requisite buffer space.
     */
    num_ptrs = 1;                       /* +1 for gr_mem[] null termination */
    num_bytes = 0;
    for (userp = src->gr_mem; userp && *userp; userp++) {
        num_ptrs++;
        num_bytes += strlen (*userp) + 1;
    }
    if (src->gr_name) {
        num_bytes += strlen (src->gr_name) + 1;
    }
    if (src->gr_passwd) {
        num_bytes += strlen (src->gr_passwd) + 1;
    }
    num_bytes += num_ptrs * (sizeof (char *));

    /*  Ensure requisite buffer space.
     */
    if (grbufp->len < num_bytes) {
        if (_xgetgrent_buf_grow (grbufp, num_bytes) < 0) {
            return (-1);
        }
    }
    /*  Copy group entry.
     */
    assert (grbufp->len >= num_bytes);
    memset (dst, 0, sizeof (*dst));
    p = grbufp->buf;

    n = num_ptrs * (sizeof (char *));
    if (num_bytes < n) {
        goto err;
    }
    dst->gr_mem = (char **) p;
    p += n;
    num_bytes -= n;

    if (_xgetgrent_copy_str
            (src->gr_name, &(dst->gr_name), &p, &num_bytes) < 0) {
        goto err;
    }
    if (_xgetgrent_copy_str
            (src->gr_passwd, &(dst->gr_passwd), &p, &num_bytes) < 0) {
        goto err;
    }
    for (i = 0; i < num_ptrs; i++) {
        if (_xgetgrent_copy_str
                (src->gr_mem [i], &(dst->gr_mem [i]), &p, &num_bytes) < 0) {
            goto err;
        }
    }
    dst->gr_gid = src->gr_gid;

    assert (p <= grbufp->buf + grbufp->len);
    return (0);

err:
    errno = ERANGE;
    return (-1);
}


static int
_xgetgrent_copy_str (const char *src, char **dstp,
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
