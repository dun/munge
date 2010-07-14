/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://munge.googlecode.com/>.
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
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "cred.h"
#include "hash.h"
#include "log.h"
#include "m_msg.h"
#include "munge_defs.h"
#include "replay.h"
#include "thread.h"
#include "timer.h"


/*****************************************************************************
 *  Private Constants
 *****************************************************************************/

#define REPLAY_ALLOC    1024


/*****************************************************************************
 *  Private Data Types
 *****************************************************************************/

union replay_key {
    struct {
      union replay_key  *next;          /* ptr for chaining by allocator     */
    }                    alloc;
    struct {
      time_t             t_expired;     /* time after which cred expires     */
      unsigned char      mac[MUNGE_MINIMUM_MD_LEN];     /* msg auth code     */
    }                    data;
};

typedef union replay_key * replay_t;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static unsigned int replay_key_f (const replay_t r);

static int replay_cmp_f (const replay_t r1, const replay_t r2);

static int replay_is_expired (replay_t r, void *key, time_t *pnow);

static replay_t replay_alloc (void);

static void replay_free (replay_t r);


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

static hash_t replay_hash = NULL;

static replay_t replay_free_list = NULL;

static pthread_mutex_t replay_free_lock = PTHREAD_MUTEX_INITIALIZER;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
replay_init (void)
{
/*  Initializes the replay detection engine.
 */
    hash_key_f keyf = (hash_key_f) replay_key_f;
    hash_cmp_f cmpf = (hash_cmp_f) replay_cmp_f;
    hash_del_f delf = (hash_del_f) replay_free;

    if ((replay_hash)) {
        return;
    }
    if (!(replay_hash = hash_create (REPLAY_HASH_SIZE, keyf, cmpf, delf))) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to allocate replay hash");
    }
    if (timer_set_relative (
      (callback_f) replay_purge, NULL, MUNGE_REPLAY_PURGE_SECS * 1000) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set replay purge timer");
    }
    return;
}


void
replay_fini (void)
{
/*  Terminates the replay detection engine.
 *
 *  XXX: Race conditions may result if the replay hash is removed while
 *    replay_purge() timers are active.  Consequently, the timer thread
 *    is canceled via timer_fini() as soon as munged's event loop is exited.
 *    And shortly _thereafter_, this routine is invoked.
 */
    if (!replay_hash) {
        return;
    }
    hash_destroy (replay_hash);
    replay_hash = NULL;
    return;
}


int
replay_insert (munge_cred_t c)
{
/*  Inserts the credential [c] into the replay hash.
 *    The credential is identified by the first N bytes of the MAC, where N
 *    is the minimum message digest length used by MUNGE.  Limiting the MAC
 *    length here helps to reduce the replay cache memory requirements.
 *  Returns 0 if the credential is successfully inserted.
 *    Returns 1 if the credential is already present (ie, replay).
 *    Returns -1 on error with errno set.
 */
    m_msg_t   m = c->msg;
    int       e;
    replay_t  r;

    if (!replay_hash) {
        errno = EPERM;
        return (-1);
    }
    if (!(r = replay_alloc ())) {
        return (-1);
    }
    r->data.t_expired = (time_t) (m->time0 + m->ttl);
    assert (c->mac_len >= sizeof (r->data.mac));
    memcpy (r->data.mac, c->mac, sizeof (r->data.mac));
    /*
     *  The replay hash key is just the replay struct itself.
     */
    if (hash_insert (replay_hash, r, r) != NULL) {
        return (0);
    }
    e = errno;
    replay_free (r);

    if (e == EEXIST) {
        return (1);
    }
    if (e == EINVAL) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Attempt to insert cred into hash using invalid args");
    }
    return (-1);
}


int
replay_remove (munge_cred_t c)
{
/*  Removes the credential [c] from the replay hash.
 */
    m_msg_t           m = c->msg;
    union replay_key  rkey_st;
    replay_t          rkey = &rkey_st;
    replay_t          r;

    if (!replay_hash) {
        errno = EPERM;
        return (-1);
    }
    /*  Compute the cred's "hash key".
     */
    rkey->data.t_expired = (time_t) (m->time0 + m->ttl);
    assert (c->mac_len >= sizeof (rkey->data.mac));
    memcpy (rkey->data.mac, c->mac, sizeof (rkey->data.mac));

    if ((r = hash_remove (replay_hash, rkey))) {
        replay_free (r);
    }
    return (r ? 0 : -1);
}


void
replay_purge (void)
{
/*  Purges the replay hash of any expired credentials.
 */
    time_t  now;
    int     n;

    if (!replay_hash) {
        return;
    }
    if (time (&now) == (time_t) -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to query current time");
    }
    n = hash_delete_if (replay_hash, (hash_arg_f) replay_is_expired, &now);
    assert (n >= 0);
    if (n > 0) {
        log_msg (LOG_DEBUG, "Purged %d credential%s from replay hash",
            n, ((n == 1) ? "" : "s"));
    }
    if (timer_set_relative (
      (callback_f) replay_purge, NULL, MUNGE_REPLAY_PURGE_SECS * 1000) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set replay purge timer");
    }
    return;
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static unsigned int
replay_key_f (const replay_t r)
{
/*  Use the first 4 bytes of the cred's mac as the hash key.
 *  While the results of this conversion are dependent on byte sex,
 *    we can ignore it since this data is local to the node.
 */
    return (* (unsigned int *) r->data.mac);
}


static int
replay_cmp_f (const replay_t r1, const replay_t r2)
{
/*  Returns zero if both replay structs [r1] and [r2] are equal.
 *    This return code may seem counter-intuitive, but it mirrors
 *    the various *cmp() functions that return zero on equality.
 */
    if (r1->data.t_expired != r2->data.t_expired) {
        return (-1);
    }
    if (memcmp (r1->data.mac, r2->data.mac, sizeof (r2->data.mac))) {
        return (-1);
    }
    return (0);
}


static int
replay_is_expired (replay_t r, void *key, time_t *pnow)
{
/*  Returns true if the replay struct [r] has expired based on the time [pnow].
 */
    if (r->data.t_expired < *pnow) {
        return (1);
    }
    return (0);
}


static replay_t
replay_alloc (void)
{
/*  Allocates a replay struct.
 *  Returns a ptr to the object, or NULL if memory allocation fails.
 */
    int         i;
    replay_t    r;

    assert (REPLAY_ALLOC > 0);

    lsd_mutex_lock (&replay_free_lock);
    if (!replay_free_list) {
        if ((replay_free_list = malloc (REPLAY_ALLOC * sizeof (*r)))) {
            for (i = 0; i < REPLAY_ALLOC - 1; i++)
                replay_free_list[i].alloc.next = &replay_free_list[i+1];
            replay_free_list[i].alloc.next = NULL;
        }
    }
    if ((r = replay_free_list)) {
        replay_free_list = r->alloc.next;
    }
    else {
        errno = ENOMEM;
    }
    lsd_mutex_unlock (&replay_free_lock);
    return (r);
}


static void
replay_free (replay_t r)
{
/*  De-allocates the replay struct [r].
 */
    assert (r != NULL);

    lsd_mutex_lock (&replay_free_lock);
    r->alloc.next = replay_free_list;
    replay_free_list = r;
    lsd_mutex_unlock (&replay_free_lock);
    return;
}
