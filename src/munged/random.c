/*****************************************************************************
 *  $Id: random.c,v 1.2 2003/05/06 20:15:02 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <munge.h>
#include <openssl/rand.h>
#include <string.h>
#include "crypto_log.h"
#include "log.h"
#include "random.h"


#define RANDOM_SEED_BYTES       1024
#define RANDOM_SEED_DEFAULT     "/dev/random"


void
random_init (const char *seed)
{
    int n = 0;

    if ((seed != NULL) && (*seed != '\0')) {
        /*
         *  FIXME: Ignore seed file if it does not have sane permissions.
         */
        if ((n = RAND_load_file (seed, RANDOM_SEED_BYTES)) > 0)
            log_msg (LOG_INFO, "PRNG seeded with %d bytes from \"%s\"",
                n, seed);
    }
    if (n < RANDOM_SEED_BYTES) {
        log_msg (LOG_NOTICE, "PRNG seeding in process ...");
        if ((n = RAND_load_file (RANDOM_SEED_DEFAULT, RANDOM_SEED_BYTES)) > 0)
            log_msg (LOG_INFO, "PRNG seeded PRNG with %d bytes from \"%s\"",
                n, RANDOM_SEED_DEFAULT);
    }
    if (n < RANDOM_SEED_BYTES) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unable to seed PRNG with adequte entropy.");
    }
    return;
}


void
random_fini (const char *seed)
{
    int n;

    if ((seed != NULL) && (*seed != '\0')) {
        n = RAND_write_file (seed);
        if (n < 0)
            log_msg (LOG_WARNING,
                "Generated PRNG seed \"%s\" without adequate entropy", seed);
        else if (n == 0)
            log_msg (LOG_WARNING, "Unable to write to PRNG seed \"%s\"", seed);
        else
            log_msg (LOG_INFO, "Wrote %d bytes to PRNG seed \"%s\"", n, seed);
    }
    RAND_cleanup ();
    return;
}


void
random_add (const void *buf, int n)
{
    assert (buf != NULL);
    assert (n > 0);

    RAND_seed (buf, n);
    return;
}


void
random_bytes (unsigned char *buf, int n)
{
    int rc;

    assert (buf != NULL);
    assert (n > 0);

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

    assert (buf != NULL);
    assert (n > 0);

    rc = RAND_pseudo_bytes (buf, n);
    if (rc == -1) {
        log_msg (LOG_ERR, "RAND method does not support RAND_pseudo_bytes()");
    }
    else if (rc == 0) {
        crypto_log_msg (LOG_WARNING);
    }
    return;
}
