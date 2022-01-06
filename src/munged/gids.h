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


#ifndef GIDS_H
#define GIDS_H


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define GIDS_GROUP_FILE         "/etc/group"


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

gids_t gids_create (int interval_secs, int do_group_stat);
/*
 *  Creates a list of supplementary GIDs for each UID based on information
 *    from getgrent().
 *  The [interval_secs] is the number of seconds between updates.
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
 *  Returns true (non-zero) if user [uid] is a member of the supplementary
 *    group [gid] according to the GIDs mapping [gids]; o/w, returns false.
 */


#endif /* !GIDS_H */
