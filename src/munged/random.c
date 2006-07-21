/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2003-2006 The Regents of the University of California.
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
    struct stat stat;
    int n = 0;
    int rc = 0;

    /*  FIXME: Check parent dirs of [seed] to ensure they have appropriate
     *    ownership and permissions.
     */
    if (seed != NULL) {
        if ((access (seed, R_OK | W_OK) < 0) && (errno != ENOENT)) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": %s", seed, strerror (errno));
            rc = -1;
        }
        else if (errno == ENOENT) {
            ; /* A missing seed is not considered an error. */
        }
        else if (lstat (seed, &stat) < 0) {
            log_msg (LOG_WARNING, "Unable to stat PRNG seed \"%s\": %s",
                seed, strerror (errno));
            rc = -1;
        }
        else if (!S_ISREG (stat.st_mode)) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": Not a regular file", seed);
            rc = -1;
        }
        else if ((stat.st_uid != 0) && (stat.st_uid != geteuid ())) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": Owned by uid=%d",
                seed, stat.st_uid);
            rc = -1;
        }
        else if (stat.st_mode & S_IWOTH) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": World-writable", seed);
            rc = -1;
        }
        else if (stat.st_mode & S_IROTH) {
            log_msg (LOG_WARNING,
                "Ignoring PRNG seed \"%s\": World-readable", seed);
            rc = -1;
        }
        else if ((n = RAND_load_file (seed, RANDOM_SEED_BYTES)) > 0) {
            log_msg (LOG_INFO, "PRNG seeded with %d bytes from \"%s\"",
                n, seed);
        }
    }
    if (n < RANDOM_SEED_BYTES) {
        log_msg (LOG_INFO, "PRNG seeding from \"%s\" in progress ...",
            RANDOM_SEED_DEFAULT);
        if ((n = RAND_load_file (RANDOM_SEED_DEFAULT, RANDOM_SEED_BYTES)) >0) {
            log_msg (LOG_INFO, "PRNG seeded with %d bytes from \"%s\"",
                n, RANDOM_SEED_DEFAULT);
        }
    }
    else {
        rc = 1;
    }
    if (n < RANDOM_SEED_BYTES) {
        if (!conf->got_force) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to seed PRNG with sufficient entropy");
        }
        else {
            log_msg (LOG_WARNING,
                    "Unable to seed PRNG with sufficient entropy");
        }
    }
    return (rc);
}


void
random_fini (const char *seed)
{
    int n;

    if (seed != NULL) {
        n = RAND_write_file (seed);
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
