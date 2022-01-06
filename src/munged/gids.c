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
 *****************************************************************************
 *  Refer to "gids.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>                  /* include before grp.h for bsd */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <munge.h>
#include "common.h"
#include "conf.h"
#include "gids.h"
#include "hash.h"
#include "log.h"
#include "munge_defs.h"
#include "timer.h"
#include "xgetgr.h"
#include "xgetpw.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************
 *
 *  The gid_hash is used to quickly lookup whether a given UID is a member of a
 *  particular supplementary group GID.  It contains a gid_head for each UID
 *  pointing to a singly-linked list of gid_nodes for each supplementary group
 *  of which that UID is a member.  The list of gid_nodes is sorted in
 *  increasing order of GIDs without duplicates.  This hash is constructed
 *  outside of the gids mutex, and switched in while the mutex is held during
 *  an update to replace the old gid_hash.
 *
 *  The uid_hash is used to cache positive & negative user lookups during
 *  the construction of a gid_hash, after which it is destroyed.  It contains
 *  uid_nodes mapping a unique null-terminated user string to a UID.  It is not
 *  persistent across gid_hash updates.
 *
 *  The ghost_hash is used to identify when a user first goes missing from the
 *  passwd file in order for the event to be logged only once; if the user is
 *  later added, the next gid_hash update will clear this user from the
 *  ghost_hash thereby allowing the event to be re-logged should the user
 *  disappear again.  This hash contains unique null-terminated user strings
 *  from calls to xgetpwnam() that fail with ENOENT.  Users are added when
 *  xgetpwnam() fails, and removed when xgetpwnam() succeeds.  A mutex is not
 *  needed when accessing this hash.  It is persistent across gid_hash updates.
 *
 *  The use of non-reentrant passwd/group functions (i.e., getpwnam & getgrent)
 *  here should not cause problems since they are only called in/from
 *  _gids_map_create(), and only one instance of that routine can be running at
 *  a time.  However, crashes have been traced to the use of getgrent() here
 *  (Issue #2) so the reentrant functions are now used.
 */


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define GHOST_HASH_SIZE 1031
#define GID_HASH_SIZE   2053
#define UID_HASH_SIZE   4099

#ifndef _GIDS_DEBUG
#define _GIDS_DEBUG     0
#endif /* !_GIDS_DEBUG */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct gids {
    pthread_mutex_t     mutex;          /* mutex for accessing struct        */
    hash_t              gid_hash;       /* hash of GIDs mappings             */
    hash_t              ghost_hash;     /* hash of missing users (ghosts!)   */
    long                timer;          /* timer ID for next GIDs map update */
    int                 interval_secs;  /* seconds between GIDs map updates  */
    int                 do_group_stat;  /* true if updates stat group file   */
    time_t              t_last_update;  /* time of last good GIDs map update */
};

struct gid_head {
    struct gid_node    *next;
    uid_t               uid;            /* gid_hash key                      */
};

struct gid_node {
    struct gid_node    *next;
    gid_t               gid;
};

struct uid_node {
    char               *user;           /* uid_hash key                      */
    uid_t               uid;
};

typedef struct uid_node * uid_node_p;
typedef struct gid_node * gid_node_p;
typedef struct gid_head * gid_head_p;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void         _gids_map_update (gids_t gids);
static hash_t       _gids_map_create (hash_t ghost_hash);
static int          _gids_user_to_uid (hash_t uid_hash, hash_t ghost_hash,
                        const char *user, uid_t *uid_resultp, xpwbuf_p pwbufp);
static int          _gids_gid_add (hash_t gid_hash, uid_t uid, gid_t gid);
static int          _gids_uid_add (hash_t uid_hash,
                        const char *user, uid_t uid);
static int          _gids_ghost_add (hash_t ghost_hash, const char *user);
static int          _gids_ghost_del (hash_t ghost_hash, const char *user);
static gid_head_p   _gids_gid_head_create (uid_t uid);
static void         _gids_gid_head_destroy (gid_head_p g);
static int          _gids_gid_head_cmp (
                        const uid_t *uid1p, const uid_t *uid2p);
static unsigned int _gids_gid_head_key (uid_t *uidp);
static gid_node_p   _gids_gid_node_create (gid_t gid);
static uid_node_p   _gids_uid_node_create (const char *user, uid_t uid);
static void         _gids_uid_node_destroy (uid_node_p u);

#if _GIDS_DEBUG
static void         _gids_gid_hash_dump (hash_t gid_hash);
static void         _gids_gid_node_dump (gid_head_p g, const uid_t *uidp,
                        const void *null);
static void         _gids_uid_hash_dump (hash_t uid_hash);
static void         _gids_uid_node_dump (uid_node_p u, const char *user,
                        const void *null);
static void         _gids_ghost_hash_dump (hash_t ghost_hash);
static void         _gids_ghost_node_dump (const char *data, const char *user,
                        const void *null);
#endif /* _GIDS_DEBUG */


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

gids_t
gids_create (int interval_secs, int do_group_stat)
{
    gids_t gids;

    if ((interval_secs < 0) || (conf->got_benchmark)) {
        log_msg (LOG_INFO, "Disabled supplementary group mapping");
        return (NULL);
    }
    if (!(gids = malloc (sizeof (*gids)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                "Failed to allocate gids struct");
    }
    if ((errno = pthread_mutex_init (&gids->mutex, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to init gids mutex");
    }
    gids->gid_hash = NULL;
    gids->ghost_hash = hash_create (GHOST_HASH_SIZE,
            (hash_key_f) hash_key_string,
            (hash_cmp_f) strcmp,
            (hash_del_f) free);
    if (!gids->ghost_hash) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate ghost hash");
    }
    gids->timer = 0;
    gids->interval_secs = interval_secs;
    gids->do_group_stat = do_group_stat;
    gids->t_last_update = 0;
    gids_update (gids);

    if (interval_secs == 0) {
        log_msg (LOG_INFO, "Disabled updates to supplementary group mapping");
    }
    else {
        log_msg (LOG_INFO,
                "Updating supplementary group mapping every %d second%s",
                interval_secs, (interval_secs == 1) ? "" : "s");
    }
    log_msg (LOG_INFO, "%s supplementary group mtime check of \"%s\"",
            (do_group_stat ? "Enabled" : "Disabled"), GIDS_GROUP_FILE);

    return (gids);
}


void
gids_destroy (gids_t gids)
{
    if (!gids) {
        return;
    }
    if ((errno = pthread_mutex_lock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock gids mutex");
    }
    if (gids->timer > 0) {
        timer_cancel (gids->timer);
        gids->timer = 0;
    }
    hash_destroy (gids->gid_hash);
    gids->gid_hash = NULL;
    hash_destroy (gids->ghost_hash);
    gids->ghost_hash = NULL;

    if ((errno = pthread_mutex_unlock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock gids mutex");
    }
    if ((errno = pthread_mutex_destroy (&gids->mutex)) != 0) {
        log_msg (LOG_ERR, "Failed to destroy gids mutex: %s",
                strerror (errno));
    }
    free (gids);
    return;
}


void
gids_update (gids_t gids)
{
    if (!gids) {
        return;
    }
    if ((errno = pthread_mutex_lock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock gids mutex");
    }
    /*  Cancel a pending update before scheduling a new one.
     */
    if (gids->timer > 0) {
        timer_cancel (gids->timer);
    }
    /*  Compute the GIDs mapping in the background by setting an expired timer.
     */
    gids->timer = timer_set_relative ((callback_f) _gids_map_update, gids, 0);
    if (gids->timer < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to set gids update timer");
    }
    /*  Reset the do_group_stat flag in case it had been disabled on error
     *    (ie, set to -1).
     */
    gids->do_group_stat = !! gids->do_group_stat;

    if ((errno = pthread_mutex_unlock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock gids mutex");
    }
    return;
}


int
gids_is_member (gids_t gids, uid_t uid, gid_t gid)
{
    int        is_member = 0;
    gid_head_p g;
    gid_node_p node;

    if (!gids) {
        return (0);
    }
    if ((errno = pthread_mutex_lock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock gids mutex");
    }
    if ((gids->gid_hash) && (g = hash_find (gids->gid_hash, &uid))) {
        assert (g->uid == uid);
        for (node = g->next; node && node->gid <= gid; node = node->next) {
            if (node->gid == gid) {
                is_member = 1;
                break;
            }
        }
    }
    if ((errno = pthread_mutex_unlock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock gids mutex");
    }
    return (is_member);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void
_gids_map_update (gids_t gids)
{
/*  Update the GIDs mapping [gids] and schedule the next update.
 */
    int    do_group_stat;
    time_t t_last_update;
    time_t t_now;
    int    do_update = 1;
    hash_t gid_hash = NULL;

    assert (gids != NULL);

    if ((errno = pthread_mutex_lock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock gids mutex");
    }
    do_group_stat = gids->do_group_stat;
    t_last_update = gids->t_last_update;

    if ((errno = pthread_mutex_unlock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock gids mutex");
    }
    if (time (&t_now) == (time_t) -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to query current time");
    }
    if (do_group_stat > 0) {

        struct stat st;

        /*  On stat() error, disable future stat()s until reset via SIGHUP.
         */
        if (stat (GIDS_GROUP_FILE, &st) < 0) {
            do_group_stat = -2;
            log_msg (LOG_ERR, "Failed to stat \"%s\": %s",
                    GIDS_GROUP_FILE, strerror (errno));
        }
        else if (st.st_mtime <= t_last_update) {
            do_update = 0;
        }
    }
    /*  Update the GIDs mapping without holding the mutex.
     */
    if (do_update) {
        gid_hash = _gids_map_create (gids->ghost_hash);
    }
    if ((errno = pthread_mutex_lock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock gids mutex");
    }
    /*  Replace the old GIDs mapping if the update was successful.
     */
    if (gid_hash != NULL) {

        hash_t gid_hash_bak = gids->gid_hash;
        gids->gid_hash = gid_hash;
        gid_hash = gid_hash_bak;

        gids->t_last_update = t_now;
    }
    /*  Change the GIDs do_group_stat flag only when the stat() first fails.
     *    This is done by setting the local do_group_stat flag above to -2 on
     *    error, but storing -1 in the gids struct here after the mutex is
     *    re-acquired.  By doing this, a SIGHUP triggered during
     *    _gids_map_update() can still reset the flag.
     */
    if (do_group_stat < -1) {
        gids->do_group_stat = -1;
    }
    /*  Schedule the next GIDs map update (if applicable).
     */
    gids->timer = 0;
    if (gids->interval_secs > 0) {
        gids->timer = timer_set_relative ((callback_f) _gids_map_update, gids,
                gids->interval_secs * 1000);
        if (gids->timer < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to schedule gids map update");
        }
    }
    if ((errno = pthread_mutex_unlock (&gids->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock gids mutex");
    }
    /*  Clean up the old hash now that the mutex has been released.
     */
    if (gid_hash != NULL) {
        hash_destroy (gid_hash);
    }
    return;
}


static hash_t
_gids_map_create (hash_t ghost_hash)
{
/*  Create a new gid_hash to map UIDs to their supplementary groups.
 *  Return a pointer to the new hash on success, or NULL on error.
 */
    static size_t   grbuflen = 0;
    static size_t   pwbuflen = 0;
    hash_t          gid_hash = NULL;
    hash_t          uid_hash = NULL;
    struct timeval  t_start;
    struct timeval  t_stop;
    int             do_group_db_close = 0;
    int             num_inits = 0;
    const int       max_inits = 16;
    struct group    gr;
    xgrbuf_p        grbufp = NULL;
    xpwbuf_p        pwbufp = NULL;
    char          **userp;
    uid_t           uid;
    int             n_users;
    double          n_seconds;

    gid_hash = hash_create (GID_HASH_SIZE,
            (hash_key_f) _gids_gid_head_key,
            (hash_cmp_f) _gids_gid_head_cmp,
            (hash_del_f) _gids_gid_head_destroy);

    if (!gid_hash) {
        log_msg (LOG_ERR, "Failed to allocate gid hash");
        goto err;
    }
    uid_hash = hash_create (UID_HASH_SIZE,
            (hash_key_f) hash_key_string,
            (hash_cmp_f) strcmp,
            (hash_del_f) _gids_uid_node_destroy);

    if (!uid_hash) {
        log_msg (LOG_ERR, "Failed to allocate uid hash");
        goto err;
    }
    if (gettimeofday (&t_start, NULL) < 0) {
        log_msg (LOG_ERR, "Failed to query current time");
        goto err;
    }
    /*  Allocate memory for both the xgetgrent() and xgetpwnam() buffers here.
     *    The xgetpwnam() buffer will be passed to _gids_user_to_uid() where it
     *    is used, but allocating it here allows the same buffer to be reused
     *    throughout a given gid_hash creation cycle.
     */
    if (!(grbufp = xgetgrbuf_create (grbuflen))) {
        log_msg (LOG_ERR, "Failed to allocate group entry buffer");
        goto err;
    }
    if (!(pwbufp = xgetpwbuf_create (pwbuflen))) {
        log_msg (LOG_ERR, "Failed to allocate passwd entry buffer");
        goto err;
    }
    do_group_db_close = 1;
restart:
    xgetgrent_init ();
    num_inits++;

    while (1) {
        if (xgetgrent (&gr, grbufp) < 0) {
            if (errno == ENOENT) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if ((errno == ERANGE) && (num_inits < max_inits)) {
                hash_reset (gid_hash);
                goto restart;
            }
            log_msg (LOG_ERR, "Failed to query group info: %s",
                    strerror (errno));
            goto err;
        }
        /*  gr_mem is a null-terminated array of pointers to the
         *    null-terminated user strings belonging to the group.
         */
        for (userp = gr.gr_mem; userp && *userp; userp++) {

            int rv = _gids_user_to_uid (uid_hash, ghost_hash,
                    *userp, &uid, pwbufp);

            if (rv == 0) {
                if (_gids_gid_add (gid_hash, uid, gr.gr_gid) < 0) {
                    goto err;
                }
            }
        }
    }
    xgetgrent_fini ();
    /*
     *  Record the final size of the xgetpwnam() and xgetgrent() buffers.
     *    This allows subsequent scans to start with buffers that will
     *    generally not need to be realloc()d.
     */
    pwbuflen = xgetpwbuf_get_len (pwbufp);
    xgetpwbuf_destroy (pwbufp);
    grbuflen = xgetgrbuf_get_len (grbufp);
    xgetgrbuf_destroy (grbufp);

    if (gettimeofday (&t_stop, NULL) < 0) {
        log_msg (LOG_ERR, "Failed to query current time");
        goto err;
    }

#if _GIDS_DEBUG
    _gids_uid_hash_dump (uid_hash);
    _gids_gid_hash_dump (gid_hash);
    _gids_ghost_hash_dump (ghost_hash);
#endif /* _GIDS_DEBUG */

    n_users = hash_count (gid_hash);
    if (n_users < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed _gids_map_create: Invalid gid hash ptr");
    }
    n_seconds = (t_stop.tv_sec - t_start.tv_sec)
        + ((t_stop.tv_usec - t_start.tv_usec) / 1e6);
    log_msg (LOG_INFO,
            "Found %d user%s with supplementary groups in %0.3f seconds",
            n_users, ((n_users == 1) ? "" : "s"), n_seconds);

    hash_destroy (uid_hash);
    return (gid_hash);

err:
    if (do_group_db_close) {
        xgetgrent_fini ();
    }
    if (pwbufp != NULL) {
        xgetpwbuf_destroy (pwbufp);
    }
    if (grbufp != NULL) {
        xgetgrbuf_destroy (grbufp);
    }
    if (uid_hash != NULL) {
        hash_destroy (uid_hash);
    }
    if (gid_hash != NULL) {
        hash_destroy (gid_hash);
    }
    return (NULL);
}


static int
_gids_user_to_uid (hash_t uid_hash, hash_t ghost_hash,
        const char *user, uid_t *uid_resultp, xpwbuf_p pwbufp)
{
/*  Lookup the UID of [user].
 *    [pwbufp] is a pre-allocated buffer for xgetpwnam() (see above comments).
 *  Set [*uid_resultp] (if non-NULL), and return 0 on success or -1 on error.
 */
    uid_node_p    u;
    uid_t         uid = UID_SENTINEL;
    struct passwd pw;

    if ((u = hash_find (uid_hash, user))) {
        uid = u->uid;
    }
    else if (xgetpwnam (user, &pw, pwbufp) == 0) {
        uid = pw.pw_uid;
        (void) _gids_uid_add (uid_hash, user, uid);
        (void) _gids_ghost_del (ghost_hash, user);
    }
    else if (errno == ENOENT) {
        (void) _gids_uid_add (uid_hash, user, uid);
        if (!hash_find (ghost_hash, user)) {
            (void) _gids_ghost_add (ghost_hash, user);
            log_msg (LOG_INFO,
                    "Failed to query passwd file for \"%s\": User not found",
                    user);
        }
    }
    else {
        log_msg (LOG_INFO, "Failed to query passwd file for \"%s\": %s",
                user, strerror (errno));
    }
    if (uid == UID_SENTINEL) {
        return (-1);
    }
    if (uid_resultp != NULL) {
        *uid_resultp = uid;
    }
    return (0);
}


static int
_gids_gid_add (hash_t gid_hash, uid_t uid, gid_t gid)
{
/*  Add supplementary group [gid] for user [uid] to the GIDs map [gid_hash].
 *  Return 1 if the entry was added, 0 if the entry already exists,
 *    or -1 on error.
 */
    gid_head_p  g;
    gid_node_p  node;
    gid_node_p *nodep;

    if (!(g = hash_find (gid_hash, &uid))) {
        if (!(g = _gids_gid_head_create (uid))) {
            log_msg (LOG_WARNING, "Failed to allocate gid head for uid=%u",
                    (unsigned int) uid);
            return (-1);
        }
        if (!hash_insert (gid_hash, &g->uid, g)) {
            log_msg (LOG_WARNING,
                    "Failed to insert gid head for uid=%u into gid hash",
                    (unsigned int) uid);
            _gids_gid_head_destroy (g);
            return (-1);
        }
    }
    assert (g->uid == uid);

    nodep = &g->next;
    while ((*nodep) && ((*nodep)->gid < gid)) {
        nodep = &(*nodep)->next;
    }
    if ((*nodep) && ((*nodep)->gid == gid)) {
        return (0);
    }
    if (!(node = _gids_gid_node_create (gid))) {
        log_msg (LOG_WARNING, "Failed to allocate gid node for uid=%u gid=%u",
                (unsigned int) uid, (unsigned int) gid);
        return (-1);
    }
    node->next = *nodep;
    *nodep = node;
    return (1);
}


static int
_gids_uid_add (hash_t uid_hash, const char *user, uid_t uid)
{
/*  Add mapping from [user] to [uid] to the hash [uid_hash].
 *    This assumes [user] does not already exist in the hash.
 *  Return 0 on success, or -1 on error.
 */
    uid_node_p u;

    if (!(u = _gids_uid_node_create (user, uid))) {
        log_msg (LOG_WARNING, "Failed to allocate uid node for \"%s\" uid=%u",
                user, (unsigned int) uid);
    }
    else if (!hash_insert (uid_hash, u->user, u)) {
        log_msg (LOG_WARNING,
                "Failed to insert uid node for \"%s\" uid=%u into uid hash",
                user, (unsigned int) uid);
        _gids_uid_node_destroy (u);
    }
    else {
        return (0);
    }
    return (-1);
}


static int
_gids_ghost_add (hash_t ghost_hash, const char *user)
{
/*  Add [user] to the [ghost_hash].
 *  Return 0 on success, or -1 on error.
 */
    char *p;

    if (!user) {
        errno = EINVAL;
    }
    else if (!(p = strdup (user))) {
        log_msg (LOG_WARNING, "Failed to copy string for \"%s\": %s",
                user, strerror (errno));
    }
    else if (!hash_insert (ghost_hash, p, p)) {
        log_msg (LOG_WARNING, "Failed to insert \"%s\" into ghost hash", user);
        free (p);
    }
    else {
        return (0);
    }
    return (-1);
}


static int
_gids_ghost_del (hash_t ghost_hash, const char *user)
{
/*  Remove [user] from the [ghost_hash].
 *  Return 1 if the entry was removed, 0 if the entry was not found,
 *    or -1 on error.
 */
    char *p;

    if (!user) {
        errno = EINVAL;
        return (-1);
    }
    p = hash_remove (ghost_hash, user);
    if (p == NULL) {
        return (0);
    }
    free (p);
    return (1);
}


static gid_head_p
_gids_gid_head_create (uid_t uid)
{
/*  Allocate and return a gid_head for [uid], or NULL on error.
 */
    gid_head_p g;

    if (!(g = malloc (sizeof (*g)))) {
        return (NULL);
    }
    g->next = NULL;
    g->uid = uid;
    return (g);
}


static void
_gids_gid_head_destroy (gid_head_p g)
{
/*  De-allocate the gid_head [g] and gid_node chain.
 */
    gid_node_p node, node_tmp;

    if (!g) {
        return;
    }
    node = g->next;
    free (g);
    while (node) {
        node_tmp = node;
        node = node->next;
        free (node_tmp);
    }
    return;
}


static int
_gids_gid_head_cmp (const uid_t *uid1p, const uid_t *uid2p)
{
/*  Hash comparison function for gid_hash keys [uid1p] and [uid2p].
 */
    if (*uid1p < *uid2p) {
        return (-1);
    }
    if (*uid1p > *uid2p) {
        return (1);
    }
    return (0);
}


static unsigned int
_gids_gid_head_key (uid_t *uidp)
{
/*  Hash key function for converting [uidp] into a gid_hash key.
 */
    return (*uidp);
}


static gid_node_p
_gids_gid_node_create (gid_t gid)
{
/*  Allocate and return a gid_node for [gid], or NULL on error.
 *  De-allocation is handled by _gids_gid_head_destroy().
 */
    gid_node_p node;

    if (!(node = malloc (sizeof (*node)))) {
        return (NULL);
    }
    node->next = NULL;
    node->gid = gid;
    return (node);
}


static uid_node_p
_gids_uid_node_create (const char *user, uid_t uid)
{
/*  Allocate and return a uid_node mapping [user] to [uid], or NULL on error.
 */
    uid_node_p u;

    if ((user == NULL) || (*user == '\0')) {
        return (NULL);
    }
    if (!(u = malloc (sizeof (*u)))) {
        return (NULL);
    }
    if (!(u->user = strdup (user))) {
        free (u);
        return (NULL);
    }
    u->uid = uid;
    return (u);
}


static void
_gids_uid_node_destroy (uid_node_p u)
{
/*  De-allocate the uid_node [u].
 */
    if (!u) {
        return;
    }
    if (u->user) {
        free (u->user);
    }
    free (u);
    return;
}


/*****************************************************************************
 *  Debug Functions
 *****************************************************************************/

#if _GIDS_DEBUG

static void
_gids_gid_hash_dump (hash_t gid_hash)
{
    int n;

    n = hash_count (gid_hash);
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed _gids_gid_hash_dump: Invalid gid hash ptr");
    }
    printf ("* GIDs Dump (%d UID%s):\n", n, ((n == 1) ? "" : "s"));
    hash_for_each (gid_hash, (hash_arg_f) _gids_gid_node_dump, NULL);
    return;
}


static void
_gids_gid_node_dump (gid_head_p g, const uid_t *uidp, const void *null)
{
    gid_node_p node;

    assert (g->uid == *uidp);

    printf ("  %-10u:", (unsigned int) g->uid);
    for (node = g->next; node; node = node->next) {
        printf (" %u", (unsigned int) node->gid);
    }
    printf ("\n");
    return;
}


static void
_gids_uid_hash_dump (hash_t uid_hash)
{
    int n;

    n = hash_count (uid_hash);
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed _gids_uid_hash_dump: Invalid uid hash ptr");
    }
    printf ("* UID Dump (%d user%s):\n", n, ((n == 1) ? "" : "s"));
    hash_for_each (uid_hash, (hash_arg_f) _gids_uid_node_dump, NULL);
    return;
}


static void
_gids_uid_node_dump (uid_node_p u, const char *user, const void *null)
{
    assert (u->user == user);

    printf ("  %-10u: %s\n", (unsigned int) u->uid, u->user);
    return;
}


static void
_gids_ghost_hash_dump (hash_t ghost_hash)
{
    int n;

    n = hash_count (ghost_hash);
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed _gids_host_hash_dump: Invalid ghost hash ptr");
    }
    printf ("* Ghost Dump (%d user%s):\n", n, ((n == 1) ? "" : "s"));
    hash_for_each (ghost_hash, (hash_arg_f) _gids_ghost_node_dump, NULL);
    return;
}


static void
_gids_ghost_node_dump (const char *data, const char *user, const void *null)
{
    assert (data == user);

    printf ("  %s\n", user);
    return;
}

#endif /* _GIDS_DEBUG */
