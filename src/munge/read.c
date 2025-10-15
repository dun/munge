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
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <munge.h>
#include "log.h"
#include "test.h"


/*****************************************************************************
 *  Read data from file pointer into a dynamically allocated buffer.
 *
 *  Reads all data from [fp] into a malloc'd buffer, ensuring the buffer
 *  contains a terminating null byte. The buffer grows exponentially to
 *  minimize realloc() calls when reading from potentially non-seekable
 *  streams.
 *
 *  Args:
 *    fp:       Input file pointer
 *    dst:      Pointer to allocated buffer (caller must free)
 *    dst_len:  Number of bytes read (not including the terminating null byte)
 *    max_size: Maximum allowed buffer size
 *
 *  The function terminates the program on error.
 *****************************************************************************/
void
read_data_from_file (FILE *fp, void **dst, int *dst_len, size_t max_size)
{
    const size_t read_chunk = 8192;
    unsigned char read_buf[read_chunk];
    unsigned char *dst_buf = NULL;
    size_t dst_used = 0;
    size_t dst_size = 0;
    size_t n;

    assert (fp != NULL);
    assert (dst != NULL);
    assert (dst_len != NULL);
    assert (max_size > 0);

#ifndef NDEBUG
    /*  Check if the client max_size limit should be bypassed in order to
     *    test libmunge enforcement of the limit.
     */
    int bypass;
    if (!test_get_env_int ("MUNGE_TEST_CLIENT_LIMIT_BYPASS", &bypass)) {
        if (bypass == 1) {
            log_msg (LOG_INFO, "Bypassing client input limit");
            max_size++;
        }
    }
#endif /* !NDEBUG */

    /*  Read data in chunks since size is unknown in advance.
     */
    while ((n = fread (read_buf, 1, sizeof read_buf, fp)) > 0) {

        /*  Check size limit before allocating more memory.
         *  Use subtraction instead of addition to avoid integer overflow.
         */
        if (dst_used > max_size - n) {
            free (dst_buf);
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Input size exceeded maximum of %lu", max_size);
        }
        /*  Grow buffer exponentially to minimize realloc() calls.
         */
        if (dst_used + n > dst_size) {
            size_t new_size = (dst_size == 0 ? read_chunk : dst_size * 2);
            if (new_size > max_size) {
                new_size = max_size;
            }
            /*  Allocate with +1 for terminating null byte.
             */
            unsigned char *new_buf = realloc (dst_buf, new_size + 1);
            if (!new_buf) {
                free (dst_buf);
                log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to allocate %lu bytes", new_size + 1);
            }
            dst_buf = new_buf;
            dst_size = new_size;
        }
        /*  Copy the new chunk into the destination buffer.
         */
        memcpy (dst_buf + dst_used, read_buf, n);
        dst_used += n;
    }
    /*  Check for read errors.
     */
    if (ferror (fp)) {
        free (dst_buf);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to read");
    }
    /*  Check for integer overflow.
     */
    if (dst_used > INT_MAX) {
        free (dst_buf);
        log_err (EMUNGE_SNAFU, LOG_ERR, "Exceeded max int value");
    }
    /*  Null-terminate if needed and store results.
     *  Note: dst_buf will be NULL if dst_used is 0.
     */
    if (dst_used > 0) {
        dst_buf[dst_used] = '\0';
    }
    *dst = dst_buf;
    *dst_len = (int) dst_used;
}
