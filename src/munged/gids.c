/*****************************************************************************
 *  $Id: gids.c,v 1.3 2004/05/01 06:17:14 dun Exp $
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
#include <pwd.h>
#include <stdlib.h>
#include <munge.h>
#include "gids.h"
#include "hash.h"
#include "log.h"


/*****************************************************************************
 *  Notes
 *****************************************************************************/
/*
 *  The hash contains a singly-linked list of gids_nodes for each UID having
 *    supplementary groups.  The GIDs in each list of gids_node are sorted in
 *    increasing order without duplicates.  The first gids_node in the list
 *    is special -- it contains the associated UID (cast into a gid_t).
 *
 *  The non-reentrant passwd/group functions are not an issue, since this
 *    routine is the only place where they are used within the daemon.
 *
 *  FIXME: The group information is only parsed during initialization.
 *    A timer needs to be added to re-parse this on a configurable basis
 *    (defaulting to hourly).  This, of course, requires locking in order to
 *    prevent the hash from being moved while a search operation is being
 *    performed during decode.  And read-write locks will need to be used to
 *    prevent the supplementary group search from serializing all decodes.
 *
 *  FIXME: Should all errors here be fatal?  Maybe throw a fatal error during
 *    initialization, but simply log the error and keep the old mapping if
 *    errors occur during subsequent re-parsing of the group information.
 */
 

/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct gids {
    hash_t             hash;
};

struct gids_node {
    struct gids_node  *next;
    gid_t              gid;
};

typedef struct gids_node * gids_node_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static int _gids_add (gids_t gids, uid_t uid, gid_t gid);
static gids_node_t _gids_node_alloc (gid_t gid);
static void _gids_node_free (gids_node_t g);
static int _gids_node_cmp (uid_t *uid1_p, uid_t *uid2_p);
static unsigned int _gids_node_key (uid_t *uid_p);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

gids_t
gids_create (void)
{
    gids_t gids;
    hash_key_f keyf = (hash_key_f) _gids_node_key;
    hash_cmp_f cmpf = (hash_cmp_f) _gids_node_cmp;
    hash_del_f delf = (hash_del_f) _gids_node_free;
    struct group *gr_ptr;
    struct passwd *pw_ptr;
    char **pp;
    int n;

    if (!(gids = malloc (sizeof (*gids)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate gids struct");
    }
    if (!(gids->hash = hash_create (0, keyf, cmpf, delf))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate gids hash");
    }
    for (;;) {
        errno = 0;
        if (!(gr_ptr = getgrent ())) {
            if (errno == 0)
                break;
            if (errno == EINTR)
                continue;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to parse group information");
        }
        for (pp = gr_ptr->gr_mem; *pp; pp++) {
            if ((pw_ptr = getpwnam (*pp))) {
                _gids_add (gids, pw_ptr->pw_uid, gr_ptr->gr_gid);
            }
        }
    }
    endgrent ();
    n = hash_count (gids->hash);
    log_msg (LOG_INFO, "Found %d user%s with supplementary groups",
        n, ((n == 1) ? "" : "s"));
    return (gids);
}


void
gids_destroy (gids_t gids)
{
    if (gids) {
        hash_destroy (gids->hash);
        free (gids);
    }
    return;
}


int
gids_is_member (gids_t gids, uid_t uid, gid_t gid)
{
    gids_node_t g;

    assert (gids != NULL);

    if ((g = hash_find (gids->hash, &uid)) != NULL) {
        assert (g->gid == (gid_t) uid);
        for (g = g->next; g && g->gid <= gid; g = g->next) {
            if (g->gid == gid)
                return (1);
        }
    }
    errno = EEXIST;
    return (0);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static int
_gids_add (gids_t gids, uid_t uid, gid_t gid)
{
    gids_node_t  g;
    gids_node_t *gp;

    if (!(g = hash_find (gids->hash, &uid))) {
        g = _gids_node_alloc ((gid_t) uid);
        if (!hash_insert (gids->hash, &g->gid, g)) {
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                "Unable to insert gids node into hash");
        }
    }
    assert ((uid_t) g->gid == uid);
    for (gp = &g->next; *gp && (*gp)->gid < gid; gp = &(*gp)->next) {
        ; /* empty */
    }
    if (*gp && ((*gp)->gid == gid)) {
        return (0);
    }
    g = _gids_node_alloc (gid);
    g->next = *gp;
    *gp = g;
    return (1);
}


static gids_node_t
_gids_node_alloc (gid_t gid)
{
    gids_node_t g;

    if (!(g = malloc (sizeof (*g)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate gids node");
    }
    g->next = NULL;
    g->gid = gid;
    return (g);
}


static void
_gids_node_free (gids_node_t g)
{
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
    return (!(*uid1_p == *uid2_p));
}


static unsigned int
_gids_node_key (uid_t *uid_p)
{
    return (*uid_p);
}


#if 0

static void
_gids_dump (gids_t gids)
{
    printf ("* GIDs Dump (%d UIDs):\n", hash_count (gids->hash));
    hash_for_each (gids->hash, (hash_arg_f) _gids_dump_node, NULL);
    return;
}


static void
_gids_dump_node (gids_node_t g, uid_t *uid_p, void *null)
{
    assert (g->gid == *uid_p);

    g = g->next;
    printf (" %5d:", *uid_p);
    while (g) {
        printf (" %d", g->gid);
        g = g->next;
    }
    printf ("\n");
    return;
}

#endif
