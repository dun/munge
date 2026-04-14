/******************************************************************************
 *  Copyright (C) 2007-2026 Lawrence Livermore National Security, LLC.
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
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>                      /* open */
#if HAVE_GETLOADAVG
#  include <stdlib.h>                   /* getloadavg */
#endif /* HAVE_GETLOADAVG */
#include <string.h>                     /* memcpy, strerror */
/*
 *  <sys/random.h> on legacy macOS defines u_int instead of standard types,
 *  causing compilation errors.  Only include it when needed.
 */
#if HAVE_SYS_RANDOM_H && (HAVE_GETRANDOM || HAVE_GETENTROPY)
#  include <sys/random.h>               /* getrandom, getentropy (macOS) */
#endif /* HAVE_SYS_RANDOM_H && (HAVE_GETRANDOM || HAVE_GETENTROPY) */
#if HAVE_GETRUSAGE
#  include <sys/resource.h>             /* getrusage */
#endif /* HAVE_GETRUSAGE */
#include <sys/stat.h>                   /* fstat */
#if HAVE_GETTIMEOFDAY
#  include <sys/time.h>                 /* gettimeofday */
#endif /* HAVE_GETTIMEOFDAY */
#include <sys/types.h>
#include <time.h>                       /* clock, clock_gettime */
#include <unistd.h>                     /* getentropy, getpid, getppid */
#include "entropy.h"
#include "fd.h"
#include "log.h"

/*  Maximum request size for entropy_read_csprng() syscall paths.
 *  For getrandom(2), reads up to this size return the full byte count and are
 *  not interrupted by signals.  For getentropy(2), this is a hard upper limit
 *  imposed by the API.
 */
#define ENTROPY_CSPRNG_MAX_REQUEST      256

/*  Pathname of the kernel urandom device.
 */
#define ENTROPY_URANDOM_PATH            "/dev/urandom"

static unsigned long _entropy_rotate (unsigned long value);

/**
 *  Read up to [dstlen] bytes of entropy into [dst] from the kernel's CSPRNG.
 *
 *  Return the number of bytes read, or -1 on error (with errno set).
 */
int
entropy_read_csprng (void *dst, size_t dstlen)
{
    size_t len;
    int rv;
    int n = -1;

    if (dst == NULL) {
        errno = EINVAL;
        return -1;
    }
#if HAVE_GETRANDOM
    /*  If the urandom source has been initialized, reads of up to 256 bytes
     *  will always return as many bytes as requested and not be interrupted
     *  by signals.  The EINTR retry is just an added precautionary measure.
     */
    len = (dstlen < ENTROPY_CSPRNG_MAX_REQUEST)
        ? dstlen
        : ENTROPY_CSPRNG_MAX_REQUEST;
    do {
        rv = getrandom (dst, len, 0);
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
        log_msg (LOG_WARNING, "Failed to fill buffer via getrandom(): %s",
                strerror (errno));
    }
    else if (rv > 0) {
        n = rv;
    }
#elif HAVE_GETENTROPY
    /*  The maximum permitted value for the length argument is 256 bytes.
     */
    len = (dstlen < ENTROPY_CSPRNG_MAX_REQUEST)
        ? dstlen
        : ENTROPY_CSPRNG_MAX_REQUEST;
    rv = getentropy (dst, len);
    if (rv < 0) {
        log_msg (LOG_WARNING, "Failed to fill buffer via getentropy(): %s",
                strerror (errno));
    }
    else if (rv == 0) {
        n = len;
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
                len = dstlen;
                rv = fd_read_n (fd, dst, len);
                if (rv < 0) {
                    log_msg (LOG_WARNING, "Failed to read from \"%s\": %s",
                            ENTROPY_URANDOM_PATH, strerror (errno));
                }
                else if (rv > 0) {
                    n = rv;
                }
            }
            if (close (fd) < 0) {
                log_msg (LOG_WARNING, "Failed to close \"%s\": %s",
                        ENTROPY_URANDOM_PATH, strerror (errno));
            }
        }
    }
    return n;
}

/**
 *  Read weak entropy into [dst].
 *
 *  This entropy comes from sources independent of the kernel's CSPRNG
 *  and may be of lower quality and not uniformly distributed.
 *
 *  The accumulator is rotated between entropic additions to better
 *  distribute entropy that may reside primarily in the low-order bits.
 *  Spin the wheel of entropy and win a prize!
 *
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
entropy_read_weak (unsigned long *dst)
{
    unsigned long e = 0;

    if (dst == NULL) {
        errno = EINVAL;
        return -1;
    }
    e = _entropy_rotate (e ^ (unsigned long) &entropy_read_weak);   /* ASLR */
    e = _entropy_rotate (e ^ (unsigned long) &e);                   /* ASLR */
    e = _entropy_rotate (e ^ (unsigned long) getpid ());
    e = _entropy_rotate (e ^ (unsigned long) getppid ());

    clock_t cpu_time = clock ();
    if (cpu_time != (clock_t) -1) {
        e = _entropy_rotate (e ^ (unsigned long) cpu_time);
    }
#if HAVE_CLOCK_GETTIME
    {
        struct timespec ts;
        if (clock_gettime (CLOCK_REALTIME, &ts) == 0) {
            e = _entropy_rotate (e ^ (unsigned long) ts.tv_sec);
            e = _entropy_rotate (e ^ (unsigned long) ts.tv_nsec);
        }
#if HAVE_DECL_CLOCK_MONOTONIC
        if (clock_gettime (CLOCK_MONOTONIC, &ts) == 0) {
            e = _entropy_rotate (e ^ (unsigned long) ts.tv_sec);
            e = _entropy_rotate (e ^ (unsigned long) ts.tv_nsec);
        }
#endif /* HAVE_DECL_CLOCK_MONOTONIC */
#if HAVE_DECL_CLOCK_PROCESS_CPUTIME_ID
        if (clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts) == 0) {
            e = _entropy_rotate (e ^ (unsigned long) ts.tv_sec);
            e = _entropy_rotate (e ^ (unsigned long) ts.tv_nsec);
        }
#endif /* HAVE_DECL_CLOCK_PROCESS_CPUTIME_ID */
    }
#elif HAVE_GETTIMEOFDAY
    {
        struct timeval tv;
        if (gettimeofday (&tv, NULL) == 0) {
            e = _entropy_rotate (e ^ (unsigned long) tv.tv_sec);
            e = _entropy_rotate (e ^ (unsigned long) tv.tv_usec);
        }
    }
#endif /* HAVE_GETTIMEOFDAY */
#if HAVE_GETRUSAGE
    {
        struct rusage usage;
        if (getrusage (RUSAGE_SELF, &usage) == 0) {
            e = _entropy_rotate (e ^ (unsigned long) usage.ru_utime.tv_usec);
            e = _entropy_rotate (e ^ (unsigned long) usage.ru_stime.tv_usec);
            e = _entropy_rotate (e ^ (unsigned long) usage.ru_minflt);
            e = _entropy_rotate (e ^ (unsigned long) usage.ru_majflt);
            e = _entropy_rotate (e ^ (unsigned long) usage.ru_nvcsw);
            e = _entropy_rotate (e ^ (unsigned long) usage.ru_nivcsw);
        }
    }
#endif /* HAVE_GETRUSAGE */
#if HAVE_GETLOADAVG
    {
        double loads[3];
        int n = getloadavg (loads, 3);
        for (int i = 0; i < n; i++) {
            unsigned long load;
            /*
             *  Safe because sizeof (unsigned long) <= sizeof (double) on all
             *  supported platforms (LP64: 8 <= 8; ILP32: 4 <= 8).
             */
            memcpy (&load, &loads[i], sizeof load);
            e = _entropy_rotate (e ^ load);
        }
    }
#endif /* HAVE_GETLOADAVG */
    *dst = e;
    return 0;
}

/**
 *  Rotate the bits in [value] based on its actual value in order to distribute
 *  entropy that may primarily reside in the low-order bits.
 *
 *  Return the rotated result.
 */
static unsigned long
_entropy_rotate (unsigned long value)
{
    unsigned long nbits = sizeof value * 8;
    unsigned long nrotate = value % nbits;

    if (nrotate == 0) {                 /* no rotation */
        return value;
    }
    if (value & 1) {                    /* rotate left if odd */
        return (value << nrotate) | (value >> (nbits - nrotate));
    }
    else {                              /* rotate right if even */
        return (value >> nrotate) | (value << (nbits - nrotate));
    }
}
