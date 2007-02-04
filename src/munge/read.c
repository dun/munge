/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory.
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define INIT_BUFSIZ 4096


int
read_data_from_file (FILE *fp, void **buf, int *len)
{
    unsigned char *bufmem;              /* base ptr to buffer memory         */
    unsigned char *buftmp;              /* tmp ptr to bufmem for realloc's   */
    unsigned char *bufptr;              /* current ptr to unused bufmem      */
    int            buflen;              /* num bytes of unused bufmem        */
    int            bufsiz;              /* size allocated for bufmem         */
    int            n;

    assert (fp != NULL);
    assert (buf != NULL);
    assert (len != NULL);

    *buf = NULL;
    *len = 0;
    errno = 0;

    if (!(bufmem = bufptr = malloc (INIT_BUFSIZ)))
        return (-1);
    buflen = bufsiz = INIT_BUFSIZ;

    for (;;) {
        n = fread (bufptr, 1, buflen, fp);
        bufptr += n;
        buflen -= n;
        if (buflen > 0) {
            if (feof (fp))
                break;
            else if (ferror (fp)) {
                if (!errno)             /* XXX: Can errno be trusted here? */
                    errno = EIO;
                goto err;
            }
        }
        else {
            if (!(buftmp = realloc (bufmem, bufsiz * 2)))
                goto err;
            bufmem = buftmp;
            bufptr = bufmem + bufsiz;
            buflen = bufsiz;
            bufsiz *= 2;
        }
    }
    n = bufptr - bufmem;
    if (!n) {
        free (bufmem);
        return (0);
    }
    /*  Adjust size of buf so it will be only 1 byte greater than len.
     *  Then NUL-terminate that last byte so it may be used as a string.
     *  This NUL is not included in len because it is not part of the file.
     */
    if (!(buftmp = realloc (bufmem, n + 1)))
        goto err;
    buftmp[n] = '\0';
    *buf = buftmp;
    *len = n;
    return (n);

err:
    free (bufmem);
    return (-1);
}


int
read_data_from_string (const char *s, void **buf, int *len)
{
    char *p;
    int   n;

    assert (buf != NULL);
    assert (len != NULL);

    *buf = NULL;
    *len = 0;

    if (!s)
        return (0);
    n = strlen (s);
    if (n == 0)
        return (0);
    if (s[n - 1] != '\n')               /* reserve space for trailing LF */
        n++;

    if (!(p = malloc (n + 1)))          /* reserve space for terminating NUL */
        return (-1);
    strcpy (p, s);                      /* strcpy() is safe to use here */
    p[n - 1] = '\n';
    p[n] = '\0';

    *buf = p;
    *len = n;
    return (n);
}
