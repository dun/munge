/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
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

#include <openssl/crypto.h>
#include <pthread.h>
#include <stdlib.h>
#include "crypto_thread.h"

#if _CRYPTO_THREAD_FUNCTIONS


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

#if HAVE_CRYPTO_DYNLOCK
struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};
#endif /* !HAVE_CRYPTO_DYNLOCK */


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static unsigned long _crypto_thread_id (void);

static void _crypto_thread_locking (int mode, int n,
    const char *file, int line);

#if HAVE_CRYPTO_DYNLOCK
static struct CRYPTO_dynlock_value * _crypto_thread_dynlock_create (
    const char *file, int line);

static void _crypto_thread_dynlock_lock (
    int mode, struct CRYPTO_dynlock_value *lock, const char *file, int line);

static void _crypto_thread_dynlock_destroy (
    struct CRYPTO_dynlock_value *lock, const char *file, int line);
#endif /* !HAVE_CRYPTO_DYNLOCK */


/*****************************************************************************
 *  Static Variables
 *****************************************************************************/

static pthread_mutex_t *crypto_mutex_buf = NULL;


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static unsigned long
_crypto_thread_id (void)
{
    return ((unsigned long) pthread_self ());
}


static void
_crypto_thread_locking (int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        if (pthread_mutex_lock (&crypto_mutex_buf[n]) != 0) {
            abort ();
        }
    }
    else {
        if (pthread_mutex_unlock (&crypto_mutex_buf[n]) != 0) {
            abort ();
        }
    }
    return;
}


#if HAVE_CRYPTO_DYNLOCK
static struct CRYPTO_dynlock_value *
_crypto_thread_dynlock_create (const char *file, int line)
{
    struct CRYPTO_dynlock_value *lock;

    if (!(lock = malloc (sizeof (struct CRYPTO_dynlock_value)))) {
        abort ();
    }
    if (pthread_mutex_init (&lock->mutex, NULL) != 0) {
        abort ();
    }
    return (lock);
}


static void
_crypto_thread_dynlock_lock (int mode, struct CRYPTO_dynlock_value *lock,
                          const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        if (pthread_mutex_lock (&lock->mutex) != 0) {
            abort ();
        }
    }
    else {
        if (pthread_mutex_unlock (&lock->mutex) != 0) {
            abort ();
        }
    }
    return;
}


static void
_crypto_thread_dynlock_destroy (struct CRYPTO_dynlock_value *lock,
                             const char *file, int line)
{
    if (pthread_mutex_destroy (&lock->mutex) != 0) {
        abort ();
    }
    free (lock);
    return;
}
#endif /* !HAVE_CRYPTO_DYNLOCK */


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

int
crypto_thread_init (void)
{
    int n;
    int i;

    if (crypto_mutex_buf) {
        return (1);
    }
    n = CRYPTO_num_locks ();
    if (!(crypto_mutex_buf = malloc (n * sizeof (pthread_mutex_t)))) {
        return (0);
    }
    for (i=0; i<n; i++) {
        pthread_mutex_init (&crypto_mutex_buf[i], NULL);
    }
    CRYPTO_set_id_callback (_crypto_thread_id);
    CRYPTO_set_locking_callback (_crypto_thread_locking);

#if HAVE_CRYPTO_DYNLOCK
    CRYPTO_set_dynlock_create_callback (_crypto_thread_dynlock_create);
    CRYPTO_set_dynlock_lock_callback (_crypto_thread_dynlock_lock);
    CRYPTO_set_dynlock_destroy_callback (_crypto_thread_dynlock_destroy);
#endif /* !HAVE_CRYPTO_DYNLOCK */

    return (1);
}


int
crypto_thread_fini (void)
{
    int n;
    int i;

    if (!crypto_mutex_buf) {
        return (0);
    }
    CRYPTO_set_id_callback (NULL);
    CRYPTO_set_locking_callback (NULL);

#if HAVE_CRYPTO_DYNLOCK
    CRYPTO_set_dynlock_create_callback (NULL);
    CRYPTO_set_dynlock_lock_callback (NULL);
    CRYPTO_set_dynlock_destroy_callback (NULL);
#endif /* !HAVE_CRYPTO_DYNLOCK */

    n = CRYPTO_num_locks ();
    for (i=0; i<n; i++) {
        pthread_mutex_destroy (&crypto_mutex_buf[i]);
    }
    free (crypto_mutex_buf);
    crypto_mutex_buf = NULL;
    return (1);
}


#endif /* _CRYPTO_THREAD_FUNCTIONS */
