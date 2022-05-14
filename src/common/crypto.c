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
#include <munge.h>
#include <pthread.h>
#include <stdlib.h>
#include "crypto.h"
#include "log.h"


/*****************************************************************************
 *  Libgcrypt Functions
 *****************************************************************************/

#if HAVE_LIBGCRYPT

#include <gcrypt.h>


#if GCRYPT_VERSION_NUMBER < 0x010600
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif /* GCRYPT_VERSION_NUMBER */


void
crypto_init (void)
{
    gcry_error_t e;
    const char  *v;

#if GCRYPT_VERSION_NUMBER < 0x010600
    /*  GCRYCTL_SET_THREAD_CBS must be set before any other Libcrypt function.
     *  Obsolete since Libgcrypt 1.6.
     */
    e = gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    if (e) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to set Libgcrypt thread callbacks: %s", gcry_strerror (e));
    }
#endif /* GCRYPT_VERSION_NUMBER */

    /*  gcry_check_version() must be called before any other Libgcrypt function
     *    (except the GCRYCTL_SET_THREAD_CBS command prior to Libgcrypt 1.6).
     */
    v = gcry_check_version (NULL);
    if (v == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to initialize Libgcrypt %s", GCRYPT_VERSION);
    }
    e = gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    if (e) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to disable Libgcrypt secure memory: %s",
            gcry_strerror (e));
    }
    e = gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    if (e) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to enable Libgcrypt quick random: %s",
            gcry_strerror (e));
    }
    e = gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (e) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to initialize Libgcrypt: %s", gcry_strerror (e));
    }
    return;
}


void
crypto_fini (void)
{
    return;
}

#endif /* HAVE_LIBGCRYPT */


/*****************************************************************************
 *  OpenSSL Functions
 *****************************************************************************/

#if HAVE_OPENSSL

#include <assert.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <string.h>

#if HAVE_OPENSSL_PROVIDER_H
#include <openssl/provider.h>
static OSSL_PROVIDER *_openssl_provider_default;
static OSSL_PROVIDER *_openssl_provider_legacy;
#endif /* HAVE_OPENSSL_PROVIDER_H */

static void _openssl_thread_setup (void);
static void _openssl_thread_cleanup (void);


#if OPENSSL_VERSION_NUMBER < 0x10100000L

static pthread_mutex_t * openssl_mutex_array = NULL;
static int openssl_mutex_array_num_locks = 0;

#if HAVE_CRYPTO_THREADID_SET_CALLBACK

static void
_openssl_thread_threadid_cb (CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric (id, (unsigned long) pthread_self ());
}

#elif HAVE_CRYPTO_SET_ID_CALLBACK

static unsigned long
_openssl_thread_id_cb (void)
{
    return ((unsigned long) pthread_self ());
}

#endif /* HAVE_CRYPTO_SET_ID_CALLBACK */

static void
_openssl_thread_lock_cb (int mode, int n, const char *file, int line)
{
    int rv;

    if (mode & CRYPTO_LOCK) {
        rv = pthread_mutex_lock (&openssl_mutex_array[n]);
        if (rv != 0) {
            errno = rv;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to lock OpenSSL mutex #%d", n);
        }
    }
    else {
        rv = pthread_mutex_unlock (&openssl_mutex_array[n]);
        if (rv != 0) {
            errno = rv;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to unlock OpenSSL mutex #%d", n);
        }
    }
    return;
}

#if HAVE_CRYPTO_DYNLOCK

struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};

static struct CRYPTO_dynlock_value *
_openssl_thread_dynlock_create_cb (const char *file, int line)
{
    struct CRYPTO_dynlock_value *lock;
    int rv;

    lock = malloc (sizeof (struct CRYPTO_dynlock_value));
    if (lock == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to allocate OpenSSL dynamic mutex");
    }
    rv = pthread_mutex_init (&lock->mutex, NULL);
    if (rv != 0) {
        errno = rv;
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to initialize OpenSSL dynamic mutex");
    }
    return (lock);
}

static void
_openssl_thread_dynlock_lock_cb (
    int mode, struct CRYPTO_dynlock_value *lock, const char *file, int line)
{
    int rv;

    if (mode & CRYPTO_LOCK) {
        rv = pthread_mutex_lock (&lock->mutex);
        if (rv != 0) {
            errno = rv;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to lock OpenSSL dynamic mutex");
        }
    }
    else {
        rv = pthread_mutex_unlock (&lock->mutex);
        if (rv != 0) {
            errno = rv;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to unlock OpenSSL dynamic mutex");
        }
    }
    return;
}

static void
_openssl_thread_dynlock_destroy_cb (
    struct CRYPTO_dynlock_value *lock, const char *file, int line)
{
    int rv;

    rv = pthread_mutex_destroy (&lock->mutex);
    if (rv != 0) {
        errno = rv;
        log_msg (LOG_ERR,
            "Failed to destroy OpenSSL dynamic mutex: %s", strerror (rv));
    }
    free (lock);
    return;
}

#endif /* HAVE_CRYPTO_DYNLOCK */

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */


void
crypto_init (void)
{
#if HAVE_ERR_LOAD_CRYPTO_STRINGS
    /*  OpenSSL < 1.1.0  */
    ERR_load_crypto_strings ();
#endif /* HAVE_ERR_LOAD_CRYPTO_STRINGS */

    _openssl_thread_setup ();

#if HAVE_OPENSSL_PROVIDER_H
    if (!(_openssl_provider_default = OSSL_PROVIDER_load (NULL, "default"))) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to load OpenSSL default provider");
    }
    /*  OpenSSL 3.0: The legacy provider is needed for implementations of
     *    Blowfish (cipher 2), CAST5 (cipher 3), and RIPEMD160 (mac 4).
     *  Treat failure as a warning since these are not default algorithms.
     */
    if (!(_openssl_provider_legacy = OSSL_PROVIDER_load (NULL, "legacy"))) {
        log_msg (LOG_WARNING, "%s: %s",
                "Failed to load OpenSSL legacy provider",
                "See OSSL_PROVIDER-legacy(7ssl) manpage for more info");
    }
#endif /* HAVE_OPENSSL_PROVIDER_H */

    return;
}


void
crypto_fini (void)
{
#if HAVE_OPENSSL_PROVIDER_H
    if (_openssl_provider_legacy != NULL) {
        if (OSSL_PROVIDER_unload (_openssl_provider_legacy) != 1) {
            log_msg (LOG_WARNING, "Failed to unload OpenSSL legacy provider");
        }
    }
    if (_openssl_provider_default != NULL) {
        if (OSSL_PROVIDER_unload (_openssl_provider_default) != 1) {
            log_msg (LOG_WARNING, "Failed to unload OpenSSL default provider");
        }
    }
#endif /* HAVE_OPENSSL_PROVIDER_H */

    _openssl_thread_cleanup ();

#if HAVE_ERR_FREE_STRINGS
    /*  OpenSSL < 1.1.0  */
    ERR_free_strings ();
#endif /* HAVE_ERR_FREE_STRINGS */

    return;
}


static void
_openssl_thread_setup (void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int i;
    int rv;

    if (openssl_mutex_array) {
        return;
    }
#if HAVE_CRYPTO_NUM_LOCKS
    /*  OpenSSL >= 0.9.4, < 1.1.0  */
    openssl_mutex_array_num_locks = CRYPTO_num_locks ();
#endif /* HAVE_CRYPTO_NUM_LOCKS */

    if (openssl_mutex_array_num_locks <= 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine requisite number of OpenSSL mutex locks");
    }
    openssl_mutex_array = calloc (openssl_mutex_array_num_locks,
        sizeof (pthread_mutex_t));
    if (openssl_mutex_array == NULL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to allocate memory for %d OpenSSL mutex%s",
            openssl_mutex_array_num_locks,
            (openssl_mutex_array_num_locks == 1) ? "" : "es");
    }
    for (i = 0; i < openssl_mutex_array_num_locks; i++) {
        rv = pthread_mutex_init (&openssl_mutex_array[i], NULL);
        if (rv != 0) {
            errno = rv;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to initialize OpenSSL mutex #%d", i);
        }
    }
#if HAVE_CRYPTO_THREADID_SET_CALLBACK
    /*  OpenSSL >= 1.0.0, < 1.1.0  */
    CRYPTO_THREADID_set_callback (_openssl_thread_threadid_cb);
#elif HAVE_CRYPTO_SET_ID_CALLBACK
    /*  OpenSSL < 1.0.0  */
    CRYPTO_set_id_callback (_openssl_thread_id_cb);
#endif /* HAVE_CRYPTO_SET_ID_CALLBACK */

#if HAVE_CRYPTO_SET_LOCKING_CALLBACK
    /*  OpenSSL < 1.1.0  */
    CRYPTO_set_locking_callback (_openssl_thread_lock_cb);
#endif /* HAVE_CRYPTO_SET_LOCKING_CALLBACK */

#if HAVE_CRYPTO_DYNLOCK
    /*  OpenSSL >= 0.9.5b-dev, < 1.1.0  */
    CRYPTO_set_dynlock_create_callback (_openssl_thread_dynlock_create_cb);
    CRYPTO_set_dynlock_lock_callback (_openssl_thread_dynlock_lock_cb);
    CRYPTO_set_dynlock_destroy_callback (_openssl_thread_dynlock_destroy_cb);
#endif /* HAVE_CRYPTO_DYNLOCK */

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    return;
}


static void
_openssl_thread_cleanup (void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int i;
    int rv;

    if (!openssl_mutex_array) {
        return;
    }
#if HAVE_CRYPTO_THREADID_SET_CALLBACK
    /*  OpenSSL >= 1.0.0, < 1.1.0  */
    CRYPTO_THREADID_set_callback (NULL);
#elif HAVE_CRYPTO_SET_ID_CALLBACK
    /*  OpenSSL < 1.0.0  */
    CRYPTO_set_id_callback (NULL);
#endif /* HAVE_CRYPTO_SET_ID_CALLBACK */

#if HAVE_CRYPTO_SET_LOCKING_CALLBACK
    /*  OpenSSL < 1.1.0  */
    CRYPTO_set_locking_callback (NULL);
#endif /* HAVE_CRYPTO_SET_LOCKING_CALLBACK */

#if HAVE_CRYPTO_DYNLOCK
    /*  OpenSSL >= 0.9.5b-dev, < 1.1.0  */
    CRYPTO_set_dynlock_create_callback (NULL);
    CRYPTO_set_dynlock_lock_callback (NULL);
    CRYPTO_set_dynlock_destroy_callback (NULL);
#endif /* HAVE_CRYPTO_DYNLOCK */

    for (i = 0; i < openssl_mutex_array_num_locks; i++) {
        rv = pthread_mutex_destroy (&openssl_mutex_array[i]);
        if (rv != 0) {
            errno = rv;
            log_msg (LOG_ERR,
                "Failed to destroy OpenSSL mutex #%d: %s",
                i, strerror (errno));
        }
    }
    free (openssl_mutex_array);
    openssl_mutex_array = NULL;
    openssl_mutex_array_num_locks = 0;

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    return;
}


#endif /* HAVE_OPENSSL */


/*****************************************************************************
 *  Common Functions
 *****************************************************************************/

int
crypto_memcmp (const void *s1, const void *s2, size_t n)
{
    const unsigned char *a = s1;
    const unsigned char *b = s2;
    size_t               i;
    unsigned char        x;

    for (i = 0, x = 0; i < n; i++) {
        x |= a[i] ^ b[i];
    }
    return (x != 0);
}
