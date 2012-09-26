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

#if   HAVE_GETGRENT_R_GNU
#define _GNU_SOURCE 1
#elif HAVE_GETGRENT_R_AIX
#define _THREAD_SAFE 1
#include <stdio.h>
#elif HAVE_GETGRENT_R_SUN
#elif HAVE_GETGRENT
#include <pthread.h>
#else
#error "getgrent() not supported"
#endif

#include <assert.h>
#include <errno.h>
#include <grp.h>
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

#define MINIMUM_GR_BUF_SIZE     4096


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

#if HAVE_GETGRENT_R_AIX
static FILE *_gr_fp;
#endif


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static int _xgetgrent_get_buf_size (void);

static int _xgetgrent_copy (const struct group *src, struct group *dst,
    char *buf, size_t buflen) _UNUSED_;

static int _xgetgrent_copy_str (const char *src, char **dst_p,
    char **buf_p, size_t *buflen_p) _UNUSED_;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

int
xgetgrent_buf_create (char **buf_p, int *buflen_p)
{
/*  Allocates a buffer for xgetgrent(), storing the result in [buf_p];
 *    the size of the buffer is returned in [buflen_p].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    static int  gr_buf_size = -1;
    char       *buf;

    if ((buf_p == NULL) || (buflen_p == NULL)) {
        errno = EINVAL;
        return (-1);
    }
    if (gr_buf_size < 0) {
        gr_buf_size = _xgetgrent_get_buf_size ();
    }
    buf = malloc (gr_buf_size);
    if (buf == NULL) {
        return (-1);
    }
    *buf_p = buf;
    *buflen_p = gr_buf_size;
    return (0);
}


void
xgetgrent_buf_destroy (char *buf)
{
/*  Destroys the buffer [buf].
 */
    if (buf != NULL) {
        free (buf);
    }
    return;
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


void
xgetgrent_fini (void)
{
/*  Portable encapsulation of endgrent().
 */
    endgrent ();
    return;
}


int
xgetgrent (struct group *gr, char *buf, size_t buflen)
{
/*  Portable encapsulation of getgrent_r().
 *  Reads the next group entry from the stream initialized by xgetgrent_init(),
 *    storing the struct group result in [gr] and additional strings in
 *    buffer [buf] of length [buflen].
 *  Returns 0 on success, or -1 on error (with errno).
 *    Returns -1 with ENOENT when there are no more entries.
 */
#if   HAVE_GETGRENT_R_GNU
    int                     rv;
    struct group           *gr_ptr;
#elif HAVE_GETGRENT_R_AIX
    int                     rv;
#elif HAVE_GETGRENT_R_SUN
    struct group           *gr_ptr;
#elif HAVE_GETGRENT
    static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
    int                     rv_mutex;
    int                     rv_copy;
    struct group           *gr_ptr;
#endif
    int                     got_eof = 0;
    int                     got_err = 0;

    if ((gr == NULL) || (buf == NULL) || (buflen <= 0)) {
        errno = EINVAL;
        return (-1);
    }
    errno = 0;

#if   HAVE_GETGRENT_R_GNU
    rv = getgrent_r (gr, buf, buflen, &gr_ptr);
    if (((rv == ENOENT) || (rv == 0)) && (gr_ptr == NULL)) {
        got_eof = 1;
    }
    else if (rv != 0) {
        got_err = 1;
        errno = rv;
    }
#elif HAVE_GETGRENT_R_AIX
    rv = getgrent_r (gr, buf, buflen, &_gr_fp);
    if (rv != 0) {
        if (errno == 0) {
            got_eof = 1;
        }
        else {
            got_err = 1;
        }
    }
#elif HAVE_GETGRENT_R_SUN
    gr_ptr = getgrent_r (gr, buf, buflen);
    if (gr_ptr == NULL) {
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
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock xgetgrent mutex");
    }
    gr_ptr = getgrent ();
    if (gr_ptr == NULL) {
        if ((errno == 0) || (errno == ENOENT)) {
            got_eof = 1;
        }
        else {
            got_err = 1;
        }
    }
    else {
        rv_copy = _xgetgrent_copy (gr_ptr, gr, buf, buflen);
    }
    if ((rv_mutex = pthread_mutex_unlock (&mutex)) != 0) {
        errno = rv_mutex;
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock xgetgrent mutex");
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
        return (-1);
    }
    return (0);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static int
_xgetgrent_get_buf_size (void)
{
/*  Returns the recommended size of the getgrent_r() caller-provided buffer.
 */
    static int n = -1;

    if (n < 0) {

#if HAVE_SYSCONF
#ifdef _SC_GETGR_R_SIZE_MAX
        n = sysconf (_SC_GETGR_R_SIZE_MAX);
#endif /* _SC_GETGR_R_SIZE_MAX */
#endif /* HAVE_SYSCONF */

        if (n <= MINIMUM_GR_BUF_SIZE) {
            n = MINIMUM_GR_BUF_SIZE;
        }
        log_msg (LOG_DEBUG, "Using gr buf size of %d", n);
    }
    return (n);
}


static int
_xgetgrent_copy (const struct group *src, struct group *dst,
                 char *buf, size_t buflen)
{
/*  Copies the group entry [src] into [dst], placing additional strings
 *    and whatnot into buffer [buf] of length [buflen].
 *  Returns 0 on success, or -1 on error (with errno).
 */
    int      num_ptrs;
    char   **user_p;
    char    *p = buf;
    size_t   nleft = buflen;
    size_t   n;
    int      i;

    assert (src != NULL);
    assert (dst != NULL);
    assert (buf != NULL);
    assert (buflen > 0);

    num_ptrs = 1;                       /* +1 for null-term of gr_mem array */
    for (user_p = src->gr_mem; user_p && *user_p; user_p++) {
        num_ptrs++;
    }
    n = num_ptrs * (sizeof (char *));
    if (nleft < n) {
        goto err;
    }
    dst->gr_mem = (char **) p;
    dst->gr_mem [num_ptrs - 1] = NULL;
    p += n;
    nleft -= n;

    if (_xgetgrent_copy_str
            (src->gr_name, &(dst->gr_name), &p, &nleft) < 0) {
        goto err;
    }
    if (_xgetgrent_copy_str
            (src->gr_passwd, &(dst->gr_passwd), &p, &nleft) < 0) {
        goto err;
    }
    for (i = 0; i < num_ptrs; i++) {
        if (_xgetgrent_copy_str
                (src->gr_mem [i], &(dst->gr_mem [i]), &p, &nleft) < 0) {
            goto err;
        }
    }
    dst->gr_gid = src->gr_gid;

    assert (p <= buf + buflen);
    return (0);

err:
    errno = ERANGE;
    return (-1);
}


static int
_xgetgrent_copy_str (const char *src, char **dst_p,
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
