/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2004-2005 The Regents of the University of California.
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


#ifndef GIDS_H
#define GIDS_H


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define GIDS_HASH_SIZE          2053


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

gids_t gids_create (void);
/*
 *  Creates a list of supplementary GIDs for each UID based on information
 *    in /etc/group.  This information will be updated according to the
 *    time interval specified by MUNGE_GROUP_PARSE_TIMER.
 *  Returns this GIDs mapping or dies trying.
 */

void gids_destroy (gids_t gids);
/*
 *  Destroys the GIDs mapping [gids].
 */

int gids_is_member (gids_t gids, uid_t uid, gid_t gid);
/*
 *  Returns true (non-zero) if user [uid] is a member of one of the
 *    supplementary group [gid] according to the GIDs mapping [gids];
 *    o/w, returns false (zero).
 */


#endif /* !GIDS_H */
