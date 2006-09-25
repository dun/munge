/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2006 The Regents of the University of California.
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <munge.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "conf.h"
#include "crypto_log.h"
#include "log.h"
#include "munge_defs.h"
#include "path.h"
#include "random.h"


#ifndef RANDOM_SEED_BYTES
#  define RANDOM_SEED_BYTES       1024
#endif /* !RANDOM_SEED_BYTES */

#ifndef RANDOM_SEED_DEFAULT
#  define RANDOM_SEED_DEFAULT     "/dev/random"
#endif /* !RANDOM_SEED_DEFAULT */


int
random_init (const char *seed)
{
    int          rnd_bytes_needed       = RANDOM_SEED_BYTES;
    int          rc                     = 0;
    int          do_unlink              = 1;
    int          got_symlink;
    struct stat  st;
    int          n;
    char         seed_dir [PATH_MAX];
    char         ebuf [1024];

    if ((rnd_bytes_needed > 0) && (seed != NULL) && (*seed != '\0')) {
        /*
         *  Check file permissions and whatnot.
         */
        got_symlink = (lstat (seed, &st) == 0) ? S_ISLNK (st.st_mode) : 0;

        if (((n = stat (seed, &st)) < 0) && (errno == ENOENT)) {
            if (!got_symlink) {
                do_unlink = 0; /* A missing seed is not considered an error. */
            }
        }
        else if (n < 0) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": %s", seed, strerror (errno));
        }
        else if (!S_ISREG (st.st_mode) || got_symlink) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": not a regular file", seed);
        }
        else if (st.st_uid != geteuid ()) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": not owned by uid=%u",
                seed, (unsigned) geteuid ());
        }
        else if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": "
                "cannot be readable or writable by group or world", seed);
        }
        else {
            do_unlink = 0;
        }
        /*  Ensure seed dir is secure against modification by others.
         */
        if (path_dirname (seed, seed_dir, sizeof (seed_dir)) < 0) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Cannot determine dirname of PRNG seed \"%s\"", seed);
        }
        n = path_is_secure (seed_dir, ebuf, sizeof (ebuf));
        if (n < 0) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Cannot check PRNG seed dir \"%s\": %s", seed_dir, ebuf);
        }
        else if ((n == 0) && (!conf->got_force)) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "PRNG seed dir is insecure: %s", ebuf);
        }
        else if (n == 0) {
            log_msg (LOG_WARNING,
                "PRNG seed dir is insecure: %s", ebuf);
        }
        /*  Remove the existing seed if it is insecure; o/w, load it.
         */
        if (do_unlink && (unlink (seed) < 0)) {
            log_msg (LOG_WARNING,
                "Unable to remove insecure PRNG seed \"%s\"", seed);
            rc = -1;
        }
        else if (do_unlink) {
            log_msg (LOG_INFO,
                "Removed insecure PRNG seed \"%s\"", seed);
        }
        else if ((n = RAND_load_file (seed, rnd_bytes_needed)) > 0) {
            log_msg (LOG_INFO,
                "PRNG seeded with %d bytes from \"%s\"", n, seed);
            rnd_bytes_needed -= n;
        }
    }
    /*  Load entropy from default source if more is needed.
     */
    if (rnd_bytes_needed > 0) {
        if ((n = RAND_load_file (RANDOM_SEED_DEFAULT, rnd_bytes_needed)) > 0) {
            log_msg (LOG_INFO, "PRNG seeded with %d bytes from \"%s\"",
                n, RANDOM_SEED_DEFAULT);
            rnd_bytes_needed -= n;
        }
    }
    if (rnd_bytes_needed > 0) {
        if (!conf->got_force)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to seed PRNG with sufficient entropy");
        else
            log_msg (LOG_WARNING,
                "Unable to seed PRNG with sufficient entropy");
    }
    else {
        rc = 1;
    }
    return (rc);
}


void
random_fini (const char *seed)
{
    mode_t  mask;
    int     n;

    if (seed != NULL) {
        mask = umask (0);
        umask (mask | 077);
        n = RAND_write_file (seed);
        umask (mask);

        if (n < 0) {
            log_msg (LOG_WARNING,
                "Generated PRNG seed \"%s\" without adequate entropy", seed);
        }
        else if (n == 0) {
            log_msg (LOG_WARNING, "Unable to write to PRNG seed \"%s\"", seed);
        }
        else {
            log_msg (LOG_INFO, "Wrote %d bytes to PRNG seed \"%s\"", n, seed);
        }
    }
    RAND_cleanup ();
    return;
}


void
random_add (const void *buf, int n)
{
    if (!buf || (n <= 0)) {
        return;
    }
    RAND_seed (buf, n);
    return;
}


void
random_bytes (unsigned char *buf, int n)
{
    int rc;

    if (!buf || (n <= 0)) {
        return;
    }
    rc = RAND_bytes (buf, n);
    if (rc == -1) {
        log_msg (LOG_ERR, "RAND method does not support RAND_bytes()");
    }
    else if (rc == 0) {
        crypto_log_msg (LOG_WARNING);
    }
    return;
}


void
random_pseudo_bytes (unsigned char *buf, int n)
{
    int rc;

    if (!buf || (n <= 0)) {
        return;
    }
    rc = RAND_pseudo_bytes (buf, n);
    if (rc == -1) {
        log_msg (LOG_ERR, "RAND method does not support RAND_pseudo_bytes()");
    }
    else if (rc == 0) {
        crypto_log_msg (LOG_WARNING);
    }
    return;
}
