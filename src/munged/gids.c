/*****************************************************************************
 *  $Id: gids.c,v 1.10 2004/09/21 20:08:27 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2004 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************
 *  Refer to "gids.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>                  /* include before grp.h for bsd */
#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <munge.h>
#include "conf.h"
#include "gids.h"
#include "hash.h"
#include "log.h"
#include "munge_defs.h"
#include "timer.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  The hash contains a singly-linked list of gids_nodes for each UID having
 *    supplementary groups.  The GIDs in each list of gids_node are sorted in
 *    increasing order without duplicates.  The first gids_node in the list
 *    is special -- it contains the associated UID (cast into a gid_t).
 *
 *  The non-reentrant passwd/group functions are not an issue since this
 *    routine is the only place where they are used within the daemon.  There
 *    will never be multiple instances of gids_create() running concurrently.
 */
 

/*****************************************************************************
 *  Constants
 *****************************************************************************/

#ifndef GIDS_DEBUG
#  define GIDS_DEBUG            0
#endif /* !GIDS_DEBUG */

#ifndef GIDS_GROUP_FILE
#  define GIDS_GROUP_FILE       "/etc/group"
#endif /* !GIDS_GROUP_FILE */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct gids {
    pthread_mutex_t     lock;           /* mutex for accessing struct        */
    hash_t              hash;           /* hash of GIDs mappings             */
};

struct gids_node {
    struct gids_node   *next;
    gid_t               gid;
};

typedef struct gids_node * gids_node_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void         _gids_update (gids_t gids);
static hash_t       _gids_hash_create (void);
static int          _gids_hash_add (hash_t hash, uid_t uid, gid_t gid);
static gids_node_t  _gids_node_alloc (gid_t gid);
static void         _gids_node_free (gids_node_t g);
static int          _gids_node_cmp (uid_t *uid1_p, uid_t *uid2_p);
static unsigned int _gids_node_key (uid_t *uid_p);

#if GIDS_DEBUG
static void         _gids_hash_dump (hash_t hash);
static void         _gids_dump_node (gids_node_t g, uid_t *uid_p, void *null);
#endif /* GIDS_DEBUG */


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

gids_t
gids_create (void)
{
    gids_t gids;

    if (!(gids = malloc (sizeof (*gids)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate gids struct");
    }
    if ((errno = pthread_mutex_init (&gids->lock, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to init gids mutex");
    }
    gids->hash = NULL;
    /*
     *  Compute the GIDs mapping in the background by setting an expired timer.
     *  Normally, I'd like this mapping to exist before the daemon starts
     *    accepting requests, but I've observed this processing to take a
     *    while on certain platforms.  The daemon can still function without
     *    a mapping -- gids_is_member() simply returns false until it exists.
     */
    if (timer_set_relative ((callback_f) _gids_update, gids, 0) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set gids timer");
    }
    return (gids);
}


void
gids_destroy (gids_t gids)
{
    hash_t h;

    if (!gids) {
        return;
    }
    if ((errno = pthread_mutex_lock (&gids->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock gids mutex");
    }
    h = gids->hash;
    gids->hash = NULL;

    if ((errno = pthread_mutex_unlock (&gids->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock gids mutex");
    }
    hash_destroy (h);

    if ((errno = pthread_mutex_destroy (&gids->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to destroy gids mutex");
    }
    free (gids);
    return;
}


int
gids_is_member (gids_t gids, uid_t uid, gid_t gid)
{
    gids_node_t g;
    int         is_member = 0;

    if (!gids) {
        errno = EINVAL;
        return (0);
    }
    if ((errno = pthread_mutex_lock (&gids->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock gids mutex");
    }
    if ((g = hash_find (gids->hash, &uid)) != NULL) {
        assert (g->gid == (gid_t) uid);
        for (g = g->next; g && g->gid <= gid; g = g->next) {
            if (g->gid == gid) {
                is_member = 1;
                break;
            }
        }
    }
    if ((errno = pthread_mutex_unlock (&gids->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock gids mutex");
    }
    return (is_member);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void
_gids_update (gids_t gids)
{
/*  Updates the GIDs mapping [gids] if needed.
 *
 *  The use of a static t_last_update here is groovy since there will
 *    never be multiple instances of this routine running concurrently.
 *    Placing t_last_update within the gids struct would potentially
 *    require locking the struct twice per function invocation: once
 *    for the stat and once for the update.
 */
    static time_t   t_last_update = 0;
    time_t          t_now;
    struct stat     st;
    int             do_update = 1;
    hash_t          hash, hash_bak;
    int             n;

    assert (gids != NULL);

    if (time (&t_now) == (time_t) -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to query current time");
    }
    if (conf->got_group_stat) {
        if (stat (GIDS_GROUP_FILE, &st) < 0) {
            log_msg (LOG_ERR, "Unable to stat \"%s\": %s",
                GIDS_GROUP_FILE, strerror (errno));
        }
        else if (st.st_mtime <= t_last_update) {
            do_update = 0;
        }
        else {
            t_now = st.st_mtime;
        }
    }
    if (do_update && (hash = _gids_hash_create ())) {

        n = hash_count (hash);
        log_msg (LOG_INFO, "Found %d user%s with supplementary groups",
            n, ((n == 1) ? "" : "s"));

#if GIDS_DEBUG
        _gids_hash_dump (hash);
#endif /* GIDS_DEBUG */

        if ((errno = pthread_mutex_lock (&gids->lock)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock gids mutex");
        }
        hash_bak = gids->hash;
        gids->hash = hash;

        if ((errno = pthread_mutex_unlock (&gids->lock)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock gids mutex");
        }
        hash_destroy (hash_bak);
        t_last_update = t_now;
    }
    if (timer_set_relative (
      (callback_f) _gids_update, gids, MUNGE_GROUP_PARSE_TIMER * 1000) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set gids timer");
    }
    return;
}


static hash_t
_gids_hash_create (void)
{
/*  Returns a new hash containing the new GIDs mapping, or NULL on error.
 */
    hash_t          hash = NULL;
    hash_key_f      keyf = (hash_key_f) _gids_node_key;
    hash_cmp_f      cmpf = (hash_cmp_f) _gids_node_cmp;
    hash_del_f      delf = (hash_del_f) _gids_node_free;
    struct group   *gr_ptr;
    struct passwd  *pw_ptr;
    char          **pp;

    if (!(hash = hash_create (GIDS_HASH_SIZE, keyf, cmpf, delf))) {
        log_msg (LOG_ERR, "Unable to allocate gids hash -- out of memory");
        goto err;
    }
    setgrent ();
    for (;;) {
        errno = 0;
        if (!(gr_ptr = getgrent ())) {
            /*
             *  In addition to returning NULL when there are no more entries,
             *    glibc-2.2.5 sets errno to ENOENT.  Deal with it.
             */
            if ((errno == 0) || (errno == ENOENT))
                break;
            if (errno == EINTR)
                continue;
            log_msg (LOG_ERR, "Unable to parse group information");
            endgrent ();
            goto err;
        }
        for (pp = gr_ptr->gr_mem; *pp; pp++) {
            if ((pw_ptr = getpwnam (*pp))) {
                if (_gids_hash_add (hash, pw_ptr->pw_uid, gr_ptr->gr_gid) <0) {
                    goto err;
                }
            }
        }
    }
    endgrent ();
    return (hash);

err:
    hash_destroy (hash);
    return (NULL);
}


static int
_gids_hash_add (hash_t hash, uid_t uid, gid_t gid)
{
/*  Adds supplementary group [gid] for user [uid] to the GIDs mapping [gids].
 *  Returns 1 if the entry was added, 0 if the entry already exists,
 *    or -1 on error.
 */
    gids_node_t  g;
    gids_node_t *gp;

    if (!(g = hash_find (hash, &uid))) {
        if (!(g = _gids_node_alloc ((gid_t) uid))) {
            log_msg (LOG_ERR, "Unable to allocate gids node -- out of memory");
            return (-1);
        }
        if (!hash_insert (hash, &g->gid, g)) {
            log_msg (LOG_ERR, "Unable to insert gids node into hash");
            _gids_node_free (g);
            return (-1);
        }
    }
    assert ((uid_t) g->gid == uid);
    for (gp = &g->next; *gp && (*gp)->gid < gid; gp = &(*gp)->next) {
        ; /* empty */
    }
    if (*gp && ((*gp)->gid == gid)) {
        return (0);
    }
    if (!(g = _gids_node_alloc (gid))) {
        log_msg (LOG_ERR, "Unable to allocate gids node -- out of memory");
        return (-1);
    }
    g->next = *gp;
    *gp = g;
    return (1);
}


static gids_node_t
_gids_node_alloc (gid_t gid)
{
/*  Returns an allocated GIDs node set to [gid], or NULL on error.
 */
    gids_node_t g;

    if (!(g = malloc (sizeof (*g)))) {
        return (NULL);
    }
    g->next = NULL;
    g->gid = gid;
    return (g);
}


static void
_gids_node_free (gids_node_t g)
{
/*  De-allocates the GIDs node chain starting at [g].
 */
    gids_node_t gtmp;

    while (g) {
        gtmp = g;
        g = g->next;
        free (gtmp);
    }
    return;
}


static int
_gids_node_cmp (uid_t *uid1_p, uid_t *uid2_p)
{
/*  Used by the hash routines to compare hash keys [uid1_p] and [uid2_p].
 */
    return (!(*uid1_p == *uid2_p));
}


static unsigned int
_gids_node_key (uid_t *uid_p)
{
/*  Used by the hash routines to convert [uid_p] into a hash key.
 */
    return (*uid_p);
}


/*****************************************************************************
 *  Debug Functions
 *****************************************************************************/

#if GIDS_DEBUG

static void
_gids_hash_dump (hash_t hash)
{
    printf ("* GIDs Dump (%d UIDs):\n", hash_count (hash));
    hash_for_each (hash, (hash_arg_f) _gids_dump_node, NULL);
    return;
}


static void
_gids_dump_node (gids_node_t g, uid_t *uid_p, void *null)
{
    assert (g->gid == *uid_p);

    printf (" %5d:", *uid_p);
    for (g = g->next; g; g = g->next) {
        printf (" %d", g->gid);
    }
    printf ("\n");
    return;
}

#endif /* GIDS_DEBUG */
