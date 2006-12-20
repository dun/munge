/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2006 The Regents of the University of California.
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


#ifndef GIDS_H
#define GIDS_H


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define GIDS_GROUP_FILE         "/etc/group"
#define GIDS_HASH_SIZE          2053
#define UIDS_HASH_SIZE          4099


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct gids * gids_t;
/*
 *  GIDs opaque data type.
 */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

gids_t gids_create (int interval, int do_group_stat);
/*
 *  Creates a list of supplementary GIDs for each UID based on information
 *    from getgrent().
 *  The [interval] is the number of seconds between updates.
 *  The [do_group_stat] flag specifies whether the /etc/group mtime is
 *    checked to determine if updates are needed.
 *  Returns a GIDs mapping or dies trying.
 */

void gids_destroy (gids_t gids);
/*
 *  Destroys the GIDs mapping [gids].
 */

void gids_update (gids_t gids);
/*
 *  Updates the GIDs mapping [gids].
 */

int gids_is_member (gids_t gids, uid_t uid, gid_t gid);
/*
 *  Returns true (non-zero) if user [uid] is a member of one of the
 *    supplementary group [gid] according to the GIDs mapping [gids];
 *    o/w, returns false (zero).
 */


#endif /* !GIDS_H */
