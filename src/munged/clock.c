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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <time.h>
#include "clock.h"


/*  Set timespec [tsp] to the current time adjusted forward by
 *    [msecs] milliseconds.
 *  Return 0 on success, or -1 on error (with errno set).
 */
int
clock_get_timespec (struct timespec *tsp, long msecs)
{
    int rv;

    if (tsp == NULL) {
        errno = EINVAL;
        return -1;
    }
    rv = clock_gettime (CLOCK_REALTIME, tsp);
    if (rv < 0) {
        return -1;
    }
    if (msecs > 0) {
        tsp->tv_sec += msecs / 1000;
        tsp->tv_nsec += (msecs % 1000) * 1000 * 1000;
        if (tsp->tv_nsec >= 1000 * 1000 * 1000) {
            tsp->tv_sec += tsp->tv_nsec / (1000 * 1000 * 1000);
            tsp->tv_nsec %= 1000 * 1000 * 1000;
        }
    }
    return 0;
}


/*  Return 1 if timespec [tsp0] <= [tsp1], 0 if not, or -1 on error.
 */
int
clock_is_timespec_le (const struct timespec *tsp0, const struct timespec *tsp1)
{
    if ((tsp0 == NULL) || (tsp1 == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (tsp0->tv_sec == tsp1->tv_sec) {
        return (tsp0->tv_nsec <= tsp1->tv_nsec);
    }
    else {
        return (tsp0->tv_sec <= tsp1->tv_sec);
    }
}


/*  Return 1 if timespec [tsp] <= the current time, 0 if not, or -1 on error.
 */
int
clock_is_timespec_expired (const struct timespec *tsp)
{
    struct timespec now;
    int rv;

    if (tsp == NULL) {
        errno = EINVAL;
        return -1;
    }
    rv = clock_get_timespec (&now, 0);
    if (rv < 0) {
        return -1;
    }
    rv = clock_is_timespec_le (tsp, &now);
    return rv;
}
