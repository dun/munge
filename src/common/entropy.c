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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#if HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif /* HAVE_SYS_RANDOM_H */
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include "entropy.h"
#include "log.h"
#include "rotate.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

/*  Pathname of the kernel urandom device.
 */
#define ENTROPY_URANDOM_PATH            "/dev/urandom"


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Read up to [buflen] bytes of entropy from the kernel's CSPRNG,
 *    storing the data in [buf].
 *  If [srcp] is not NULL, it will be set to a static string identifying
 *    the entropy source on success or NULL on error.
 *  Return the number of bytes read, or -1 on error (with errno set).
 */
int
entropy_read (void *buf, size_t buflen, const char **srcp)
{
    size_t       len;
    int          rv;
    int          n = -1;
    const char  *src = NULL;

    if (buf == NULL) {
        errno = EINVAL;
        return -1;
    }
#if HAVE_GETRANDOM
    /*
     *  If the urandom source has been initialized, reads of up to 256 bytes
     *    will always return as many bytes as requested and not be interrupted
     *    by signals.  No such guarantees apply for larger buffer sizes.
     */
    len = MIN(256, buflen);
    do {
        rv = getrandom (buf, len, 0);
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
        log_msg (LOG_WARNING, "Failed to fill buffer via getrandom(): %s",
                strerror (errno));
    }
    else if (rv > 0) {
        n = rv;
        src = "getrandom()";
    }
#elif HAVE_GETENTROPY
    /*
     *  The maximum buffer size permitted is 256 bytes.
     */
    len = MIN(256, buflen);
    rv = getentropy (buf, len);
    if (rv < 0) {
        log_msg (LOG_WARNING, "Failed to fill buffer via getentropy(): %s",
                strerror (errno));
    }
    else if (rv == 0) {
        n = len;
        src = "getentropy()";
    }
#endif /* HAVE_GETENTROPY */

    if (n < 0) {

        int fd;
        struct stat st;

        do {
            fd = open (ENTROPY_URANDOM_PATH, O_RDONLY | O_NONBLOCK);
        } while ((fd < 0) && (errno == EINTR));

        if (fd < 0) {
            log_msg (LOG_WARNING, "Failed to open \"%s\": %s",
                    ENTROPY_URANDOM_PATH, strerror (errno));
        }
        else {
            if (fstat (fd, &st) < 0) {
                log_msg (LOG_WARNING, "Failed to stat \"%s\": %s",
                        ENTROPY_URANDOM_PATH, strerror (errno));
            }
            else if (!S_ISCHR (st.st_mode)) {
                errno = ENODEV;
                log_msg (LOG_WARNING, "Failed to validate \"%s\": "
                        "not a character device (type=%07o)",
                        ENTROPY_URANDOM_PATH, (st.st_mode & S_IFMT));
            }
            else {
                len = buflen;
                rv = fd_read_n (fd, buf, len);
                if (rv < 0) {
                    log_msg (LOG_WARNING, "Failed to read from \"%s\": %s",
                            ENTROPY_URANDOM_PATH, strerror (errno));
                }
                else if (rv > 0) {
                    n = rv;
                    src = "\"" ENTROPY_URANDOM_PATH "\"";
                }
            }
            if (close (fd) < 0) {
                log_msg (LOG_WARNING, "Failed to close \"%s\": %s",
                        ENTROPY_URANDOM_PATH, strerror (errno));
            }
        }
    }
    if (srcp != NULL) {
        *srcp = src;
    }
    return n;
}


/*  Read entropy into the unsigned integer referenced by [up].
 *  This entropy will be from sources independent of the kernel's CSPRNG.
 *    It may be of lower quality and not uniformly distributed.
 *  The bits in the uint arg are rotated between entropic additions to better
 *    distribute the entropy.  Spin the wheel of entropy and win a prize!
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
entropy_read_uint (unsigned *up)
{
    pid_t          pid;
    clock_t        cpu_time;
    struct timeval tv;

    if (up == NULL) {
        errno = EINVAL;
        return -1;
    }
    *up = 0;

    pid = getpid ();
    *up ^= (unsigned) pid;
    rotate_left (up, *up);

    pid = getppid ();
    *up ^= (unsigned) pid;
    rotate_right (up, *up);

    cpu_time = clock ();
    if (cpu_time != (clock_t) -1) {
        *up ^= (unsigned) cpu_time;
        rotate_left (up, *up);
    }
    /*  FIXME: Replace gettimeofday() (usec resolution) with
     *    clock_gettime() (nsec resolution) for more entropy.
     */
    if (gettimeofday (&tv, NULL) == 0) {
        *up ^= (unsigned) tv.tv_sec;
        rotate_right (up, *up);
        *up ^= (unsigned) tv.tv_usec;
        rotate_left (up, *up);
    }
    return 0;
}
