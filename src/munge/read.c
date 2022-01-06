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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <munge.h>
#include "log.h"
#include "munge_defs.h"


#define INITIAL_BUFFER_SIZE     4096
#define MAXIMUM_BUFFER_SIZE     MUNGE_MAXIMUM_REQ_LEN
/*
 *  MUNGE_MAXIMUM_REQ_LEN (in munge_defs.h) specifies the maximum size of a
 *    request message transmitted over the unix domain socket.  Since messages
 *    greater than this length will be rejected, MAXIMUM_BUFFER_SIZE is used to
 *    limit the size of the memory allocation for bufmem.
 */


void
read_data_from_file (FILE *fp, void **buf, int *len)
{
    unsigned char *bufmem;              /* base ptr to buffer memory         */
    unsigned char *bufptr;              /* current ptr to unused bufmem      */
    unsigned char *buftmp;              /* tmp ptr to bufmem for realloc()   */
    size_t         bufsiz;              /* size allocated for bufmem         */
    size_t         buflen;              /* num bytes of unused bufmem        */
    size_t         bufuse;              /* num bytes of used bufmem          */
    size_t         n;

    assert (fp != NULL);
    assert (buf != NULL);
    assert (len != NULL);

    bufsiz = INITIAL_BUFFER_SIZE;
    bufmem = bufptr = malloc (bufsiz);
    if (bufmem == NULL) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to allocate %lu bytes", bufsiz);
    }
    buflen = bufsiz;

    /*  Since this reads from a standard I/O stream, there is no guarantee that
     *    the stream provides random access (e.g., when reading from a pipe).
     *    As such, it cannot rely on seeking to the end of the stream to
     *    determine the file length before seeking back to the beginning to
     *    start reading.  Consequently, this routine realloc()s the buffer to
     *    grow it as needed while reading from the fp steam.
     */
    for (;;) {
        n = fread (bufptr, 1, buflen, fp);
        bufptr += n;
        buflen -= n;
        if (buflen > 0) {
            if (feof (fp)) {
                break;
            }
            else if (ferror (fp)) {
                log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to read from file");
            }
            else {
                log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to read from file: Unexpected short count");
            }
        }
        assert (buflen == 0);
        assert (bufsiz == bufptr - bufmem);
        bufuse = bufsiz;
        bufsiz *= 2;
        if (bufsiz > MAXIMUM_BUFFER_SIZE) {
            free (bufmem);
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Exceeded maximum memory allocation");
        }
        buftmp = realloc (bufmem, bufsiz);
        if (buftmp == NULL) {
            free (bufmem);
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                "Failed to allocate %lu bytes", bufsiz);
        }
        buflen = bufsiz - bufuse;
        bufptr = buftmp + bufuse;
        bufmem = buftmp;
    }
    n = bufptr - bufmem;
    if (n == 0) {
        free (bufmem);
        *buf = NULL;
        *len = 0;
        return;
    }
    /*  If the fp has exactly 'len' bytes remaining, fread (ptr, 1, len, fp)
     *    will return a value equal to 'len'.  But the EOF will not be detected
     *    until the next fread() which will return a value of 0.  Consequently,
     *    realloc() will double the buffer before this final iteration of the
     *    loop thereby guaranteeing (buflen > 0).  The if-guard here is just
     *    for safety/paranoia.
     */
    assert (buflen > 0);
    if (buflen > 0) {
        bufmem[n] = '\0';
    }
    if (n > INT_MAX) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Exceeded maximum file size");
    }
    *buf = bufmem;
    *len = (int) n;
    return;
}


void
read_data_from_string (const char *s, void **buf, int *len)
{
    size_t  n;
    char   *p;

    assert (buf != NULL);
    assert (len != NULL);

    *buf = NULL;
    *len = 0;

    if (s == NULL) {
        return;
    }
    n = strlen (s);
    if (n == 0) {
        return;
    }
    p = malloc (n + 1);
    if (p == NULL) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to allocate %lu bytes", n + 1);
    }
    strncpy (p, s, n + 1);
    p[n] = '\0';        /* null termination here is technically unnecessary */

    if (n > INT_MAX) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Exceeded maximum string size");
    }
    *buf = p;
    *len = (int) n;
    return;
}
