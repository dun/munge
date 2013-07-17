/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2013 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://munge.googlecode.com/>.
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
#include <fcntl.h>
#include <munge.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "common.h"
#include "conf.h"
#include "crypto.h"
#include "log.h"
#include "munge_defs.h"
#include "path.h"
#include "random.h"
#include "timer.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#ifndef RANDOM_SEED_BYTES
#  define RANDOM_SEED_BYTES             1024
#endif /* !RANDOM_SEED_BYTES */

#ifndef RANDOM_SEED_DEVICE
#  define RANDOM_SEED_DEVICE            "/dev/urandom"
#endif /* !RANDOM_SEED_DEVICE */

#ifndef RANDOM_SEED_STIR_BYTES
#  define RANDOM_SEED_STIR_BYTES        16
#endif /* !RANDOM_SEED_STIR_BYTES */

#ifndef RANDOM_SEED_STIR_MAX_SECS
#  define RANDOM_SEED_STIR_MAX_SECS     3600
#endif /* !RANDOM_SEED_STIR_MAX_SECS */

#ifndef RANDOM_SEED_STIR_MIN_SECS
#  define RANDOM_SEED_STIR_MIN_SECS     1
#endif /* !RANDOM_SEED_STIR_MIN_SECS */


/*****************************************************************************
 *  Private Data
 *****************************************************************************/

static long _random_timer_id = 0;       /* ID for scheduled stir fn callback */


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

int  _random_read_seed (const char *filename, int num_bytes);
int  _random_write_seed (const char *filename, int num_bytes);
void _random_cleanup (void);
void _random_add (const void *buf, int n);
void _random_bytes (unsigned char *buf, int n);
void _random_pseudo_bytes (unsigned char *buf, int n);
void _random_seed_stir_callback (void *_arg_not_used_);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

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

    /*  Load entropy from seed file.
     */
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
                "Ignoring PRNG seed \"%s\": not owned by UID %u",
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
                "Failed to determine dirname of PRNG seed \"%s\"", seed);
        }
        n = path_is_secure (seed_dir, ebuf, sizeof (ebuf));
        if (n < 0) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to check PRNG seed dir \"%s\": %s", seed_dir, ebuf);
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
                "Failed to remove insecure PRNG seed \"%s\"", seed);
            rc = -1;
        }
        else if (do_unlink) {
            log_msg (LOG_INFO,
                "Removed insecure PRNG seed \"%s\"", seed);
        }
        else if ((n = _random_read_seed (seed, rnd_bytes_needed)) > 0) {
            log_msg (LOG_INFO,
                "PRNG seeded with %d bytes from \"%s\"", n, seed);
            rnd_bytes_needed -= n;
        }
    }
    /*  Load entropy from default source if more is needed.
     */
    if (rnd_bytes_needed > 0) {
        n = _random_read_seed (RANDOM_SEED_DEVICE, rnd_bytes_needed);
        if (n > 0) {
            log_msg (LOG_INFO, "PRNG seeded with %d bytes from \"%s\"",
                n, RANDOM_SEED_DEVICE);
            rnd_bytes_needed -= n;
        }
    }
    /*  Warn if sufficient entropy is not available.
     */
    if (rnd_bytes_needed > 0) {
        if (!conf->got_force)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to seed PRNG with sufficient entropy");
        else
            log_msg (LOG_WARNING,
                "Failed to seed PRNG with sufficient entropy");
    }
    else {
        rc = 1;
    }
    /*  Stir the initial state of the entropy pool.  This helps to protect
     *    against multiple instances starting with the same seed: for example,
     *    starting after a previous instance that did not shutdown gracefully
     *    (so its final seed state was not written), or cloning a VM.
     */
    random_stir ();
    /*
     *  Schedule repeated stirrings of the entropy pool.
     *  The callback won't run until after timer_init() is invoked in main(),
     *    so random_stir() is still needed above to stir the initial state of
     *    the entropy pool before the PRNG is used.
     */
    if (conf->got_benchmark) {
        log_msg (LOG_INFO, "Disabled PRNG entropy pool stirring");
        return (rc);
    }
    _random_timer_id = timer_set_relative (
            (callback_f) _random_seed_stir_callback, NULL,
            RANDOM_SEED_STIR_MIN_SECS * 1000);

    if (_random_timer_id < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to set PRNG stir timer");
    }
    return (rc);
}


void
random_fini (const char *seed)
{
    mode_t  mask;
    int     n;

    if (_random_timer_id > 0) {
        timer_cancel (_random_timer_id);
    }
    random_stir ();

    if (seed != NULL) {

        mask = umask (0);
        umask (mask | 077);
        n = _random_write_seed (seed, RANDOM_SEED_BYTES);
        umask (mask);

        if (n > 0) {
            log_msg (LOG_INFO, "Wrote %d bytes to PRNG seed \"%s\"", n, seed);
        }
    }
    _random_cleanup ();
    return;
}


void
random_add (const void *buf, int n)
{
    if (!buf || (n <= 0)) {
        return;
    }
    _random_add (buf, n);
    return;
}


void
random_bytes (unsigned char *buf, int n)
{
    if (!buf || (n <= 0)) {
        return;
    }
    _random_bytes (buf, n);
    return;
}


void
random_pseudo_bytes (unsigned char *buf, int n)
{
    if (!buf || (n <= 0)) {
        return;
    }
    _random_pseudo_bytes (buf, n);
    return;
}


void
random_stir (void)
{
    int            fd;
    int            n;
    unsigned char  stir_buf [RANDOM_SEED_STIR_BYTES];

    log_msg (LOG_DEBUG, "Stirring PRNG entropy pool");

    /*  Stir the entropy pool with some pseudorandom data.
     */
    fd = open (RANDOM_SEED_DEVICE, O_RDONLY | O_NONBLOCK);
    if (fd >= 0) {
        n = read (fd, stir_buf, sizeof (stir_buf));
        if (n > 0) {
            _random_add (stir_buf, n);
        }
        (void) close (fd);
    }
    return;
}


/*****************************************************************************
 *  Private Functions (Libgcrypt)
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <assert.h>
#include <gcrypt.h>
#include "fd.h"

int
_random_read_seed (const char *filename, int num_bytes)
{
    int            fd;
    int            num_left;
    int            num_want;
    int            n;
    unsigned char  buf [RANDOM_SEED_BYTES];
    gcry_error_t   e;

    assert (filename != NULL);
    assert (num_bytes > 0);

    if ((fd = open (filename, O_RDONLY)) < 0) {
        if (errno == ENOENT) {
            return (0);
        }
        log_msg (LOG_WARNING, "Failed to open PRNG seed \"%s\": %s",
            filename, strerror (errno));
        return (-1);
    }
    num_left = num_bytes;
    while (num_left > 0) {
        num_want = (num_left < sizeof (buf)) ? num_left : sizeof (buf);
        n = fd_read_n (fd, buf, num_want);
        if (n < 0) {
            log_msg (LOG_WARNING, "Failed to read from PRNG seed \"%s\": %s",
                filename, strerror (errno));
            break;
        }
        if (n == 0) {
            break;
        }
        e = gcry_random_add_bytes (buf, n, -1);
        if (e) {
            log_msg (LOG_WARNING,
                "Failed to add %d byte%s to entropy pool: %s",
                n, (n == 1 ? "" : "s"), gcry_strerror (e));
            break;
        }
        num_left -= n;
    }
    if (close (fd) < 0) {
        log_msg (LOG_WARNING, "Failed to close PRNG seed \"%s\": %s",
            filename, strerror (errno));
    }
    gcry_fast_random_poll ();
    return (num_bytes - num_left);
}


int
_random_write_seed (const char *filename, int num_bytes)
{
    int            fd;
    int            num_left;
    int            num_want;
    int            n;
    unsigned char  buf [RANDOM_SEED_BYTES];

    assert (filename != NULL);
    assert (num_bytes > 0);

    (void) unlink (filename);
    if ((fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
        log_msg (LOG_WARNING, "Failed to create PRNG seed \"%s\": %s",
            filename, strerror (errno));
        return (-1);
    }
    num_left = num_bytes;
    while (num_left > 0) {
        num_want = (num_left < sizeof (buf)) ? num_left : sizeof (buf);
        gcry_create_nonce (buf, num_want);
        n = fd_write_n (fd, buf, num_want);
        if (n < 0) {
            log_msg (LOG_WARNING, "Failed to write to PRNG seed \"%s\": %s",
                filename, strerror (errno));
            break;
        }
        num_left -= n;
    }
    if (close (fd) < 0) {
        log_msg (LOG_WARNING, "Failed to close PRNG seed \"%s\": %s",
            filename, strerror (errno));
    }
    return (num_bytes - num_left);
}


void
_random_cleanup (void)
{
    return;
}


void
_random_add (const void *buf, int n)
{
    gcry_error_t e;

    assert (buf != NULL);
    assert (n > 0);

    e = gcry_random_add_bytes (buf, n, -1);
    if (e) {
        log_msg (LOG_WARNING, "Failed to add %d byte%s to entropy pool: %s",
            n, (n == 1 ? "" : "s"), gcry_strerror (e));
    }
    gcry_fast_random_poll ();
    return;
}


void
_random_bytes (unsigned char *buf, int n)
{
    assert (buf != NULL);
    assert (n > 0);

    gcry_fast_random_poll ();
    gcry_randomize (buf, n, GCRY_VERY_STRONG_RANDOM);
    return;
}


void
_random_pseudo_bytes (unsigned char *buf, int n)
{
    assert (buf != NULL);
    assert (n > 0);

    gcry_create_nonce (buf, n);
    return;
}

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  Private Functions (OpenSSL)
 *****************************************************************************/

#if HAVE_OPENSSL

#include <assert.h>
#include <openssl/rand.h>

int
_random_read_seed (const char *filename, int num_bytes)
{
    assert (filename != NULL);
    assert (num_bytes > 0);

    return (RAND_load_file (filename, num_bytes));
}


int
_random_write_seed (const char *filename, int num_bytes)
{
    int n;

    assert (filename != NULL);
    assert (num_bytes > 0);

    n = RAND_write_file (filename);
    if (n < 0) {
        log_msg (LOG_WARNING,
            "PRNG seed \"%s\" generated with insufficient entropy", filename);
    }
    else if (n == 0) {
        log_msg (LOG_WARNING, "Failed to create PRNG seed \"%s\"", filename);
    }
    return (n);
}


void
_random_cleanup (void)
{
    RAND_cleanup ();
    return;
}


void
_random_add (const void *buf, int n)
{
    assert (buf != NULL);
    assert (n > 0);

    RAND_seed (buf, n);
    return;
}


void
_random_bytes (unsigned char *buf, int n)
{
    int rc;

    assert (buf != NULL);
    assert (n > 0);

    rc = RAND_bytes (buf, n);
    if (rc == -1) {
        log_msg (LOG_ERR,
            "RAND_bytes not supported by OpenSSL RAND method");
    }
    else if (rc == 0) {
        openssl_log_msg (LOG_WARNING);
    }
    return;
}


void
_random_pseudo_bytes (unsigned char *buf, int n)
{
    int rc;

    assert (buf != NULL);
    assert (n > 0);

    rc = RAND_pseudo_bytes (buf, n);
    if (rc == -1) {
        log_msg (LOG_ERR,
            "RAND_pseudo_bytes not supported by OpenSSL RAND method");
    }
    else if (rc == 0) {
        openssl_log_msg (LOG_WARNING);
    }
    return;
}

#endif /* HAVE_OPENSSL */


/*****************************************************************************
 *  Private Functions (Common)
 *****************************************************************************/

void
_random_seed_stir_callback (void *_arg_not_used_)
{
    static int      timeout_secs = RANDOM_SEED_STIR_MIN_SECS;
    struct timeval  tv;
    int             msecs;

    _random_timer_id = 0;

    /*  Disable repeated stirrings if the mininum timeout is set to 0.
     */
    if (timeout_secs <= 0) {
        return;
    }
    random_stir ();

    /*  Stir the entropy pool with the current time.  There should be some
     *    entropy in the tv_usec component -- up to 20 bits, but probably more
     *    in the range of 5-10 bits.  The entropy arises from the uncertainty
     *    as to precisely when the callback executes.
     */
    if (gettimeofday (&tv, NULL) == 0) {
        _random_add (&tv.tv_usec, sizeof (tv.tv_usec));
    }
    /*  Perform an exponential backoff up to the maximum timeout.  This allows
     *    for vigorous stirring of the entropy pool when the daemon is started.
     */
    if (timeout_secs < RANDOM_SEED_STIR_MAX_SECS) {
        timeout_secs = MIN(timeout_secs * 2, RANDOM_SEED_STIR_MAX_SECS);
    }
    /*  The 10 low-order bits of the current time are used to mix things up and
     *    stagger subsequent callbacks by up to 1023ms.
     */
    msecs = (timeout_secs * 1000) + (tv.tv_usec & 0x3FF);

    _random_timer_id = timer_set_relative (
            (callback_f) _random_seed_stir_callback, NULL, msecs);

    if (_random_timer_id < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to set PRNG stir timer");
    }
    return;
}
