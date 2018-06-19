/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2018 Lawrence Livermore National Security, LLC.
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "conf.h"
#include "entropy.h"
#include "fd.h"
#include "log.h"
#include "munge_defs.h"
#include "str.h"


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Create a key for the config in [confp].
 */
void
create_key (conf_t *confp)
{
    unsigned char  buf [MUNGE_KEY_LEN_MAX_BYTES];
    unsigned char *p;
    int            fd;
    int            n;
    int            n_written;
    int            rv;
    const char    *src;

    assert (confp != NULL);
    assert (confp->key_num_bytes <= MUNGE_KEY_LEN_MAX_BYTES);
    assert (confp->key_num_bytes >= MUNGE_KEY_LEN_MIN_BYTES);

    if (confp->do_force) {
        rv = unlink (confp->key_path);
        if ((rv == -1) && (errno != ENOENT)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to remove \"%s\"",
                    confp->key_path);
        }
    }
    fd = open (confp->key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to create \"%s\"",
                confp->key_path);
    }
    p = buf;
    n = confp->key_num_bytes;
    while (n > 0) {
        rv = entropy_read (p, n, &src);
        if (rv <= 0) {
            break;
        }
        p += rv;
        n -= rv;
        log_msg (LOG_DEBUG, "Read %d bytes of entropy from %s", rv, src);
    }
    n_written = fd_write_n (fd, buf, confp->key_num_bytes);
    if (n_written != confp->key_num_bytes) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to write %d bytes to \"%s\"",
                confp->key_num_bytes, confp->key_path);
    }
    rv = close (fd);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close \"%s\"",
                confp->key_path);
    }
    (void) memburn (buf, 0, sizeof (buf));
    if (confp->do_verbose) {
        log_msg (LOG_INFO, "Created \"%s\" with %d-bit key",
                confp->key_path, confp->key_num_bytes * 8);
    }
}
