/*****************************************************************************
 *  $Id: replay.c,v 1.3 2004/04/03 01:12:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-155910.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "cred.h"
#include "hash.h"
#include "log.h"
#include "munge_defs.h"
#include "munge_msg.h"
#include "replay.h"
#include "thread.h"
#include "timer.h"


/*****************************************************************************
 *  Private Constants
 *****************************************************************************/

#define REPLAY_ALLOC 256


/*****************************************************************************
 *  Private Data Types
 *****************************************************************************/

struct replay_key {
    struct replay_key  *next;           /* ptr for chaining by allocator     */
    time_t              t_expired;      /* time after which cred expires     */
    int                 mac_len;        /* length of mac data                */
    unsigned char       mac[MAX_MAC];   /* message authentication code       */
};

typedef struct replay_key * replay_t;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static unsigned int replay_key_f (const replay_t r);

static int replay_cmp_f (const replay_t r1, const replay_t r2);

static int replay_is_expired (replay_t r, time_t *pnow);

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
      (callback_f) replay_purge, NULL, MUNGE_REPLAY_PURGE_TIMER * 1000) < 0) {
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
 *    And shortly _thereafter_, this routine is invoked from destroy_conf().
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
/*  Returns 0 if the credential is successfully inserted.
 *    Returns 1 if the credential is already present (ie, replay).
 *    Returns -1 on error with errno set.
 */
    int                     e;
    replay_t                r;
    struct munge_msg_v1    *m1;

    if (!replay_hash) {
        errno = EPERM;
        return (-1);
    }
    m1 = c->msg->pbody;

    /*  Attempt to insert a replay obj for this cred into the hash.
     */
    if (!(r = replay_alloc ())) {
        return (-1);
    }
    r->t_expired = (time_t) (m1->time0 + m1->ttl);
    r->mac_len = c->mac_len;
    memcpy (r->mac, c->mac, c->mac_len);

    if (hash_insert (replay_hash, r, r) != NULL) {
        return (0);
    }
    e = errno;

    /*  De-allocate the replay obj if it couldn't be inserted.
     */
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
      (callback_f) replay_purge, NULL, MUNGE_REPLAY_PURGE_TIMER * 1000) < 0) {
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
/*  Use the first 8 bytes or so (depending on the size of a u_int)
 *    of the cred's mac as the hash key.
 *  While the results of this conversion are dependent on byte sex,
 *    we can ignore it since this data is local to the node.
 */
    return (* (unsigned int *) r->mac);
}


static int
replay_cmp_f (const replay_t r1, const replay_t r2)
{
/*  Returns zero if both replay structs [r1] and [r2] are equal.
 *    This return code may seem counter-intuitive, but it mirrors
 *    the various *cmp() functions that return zero on equality.
 */
    if (r1->t_expired != r2->t_expired) {
        return (-1);
    }
    if (r1->mac_len != r2->mac_len) {
        return (-1);
    }
    if (memcmp (r1->mac, r2->mac, r2->mac_len)) {
        return (-1);
    }
    return (0);
}


static int
replay_is_expired (replay_t r, time_t *pnow)
{
/*  Returns true if the replay struct [r] has expired based on the time [pnow].
 */
    if (r->t_expired < *pnow) {
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
    int         i, n;
    replay_t    r;

    assert (REPLAY_ALLOC > 0);

    lsd_mutex_lock (&replay_free_lock);
    if (!replay_free_list) {
        n = sizeof (struct replay_key);
        if ((replay_free_list = calloc (REPLAY_ALLOC, n))) {
            for (i = 0; i < REPLAY_ALLOC - 1; i++)
                replay_free_list[i].next = &replay_free_list[i+1];
            replay_free_list[i].next = NULL;
        }
    }
    if ((r = replay_free_list))
        replay_free_list = r->next;
    else
        errno = ENOMEM;
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
    r->next = replay_free_list;
    replay_free_list = r;
    lsd_mutex_unlock (&replay_free_lock);
    return;
}
