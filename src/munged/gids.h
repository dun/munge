/*****************************************************************************
 *  $Id: gids.h,v 1.1 2004/04/16 22:15:06 dun Exp $
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
 *****************************************************************************/


#ifndef GIDS_H
#define GIDS_H


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
 *    in /etc/group.
 *  Returns this GIDs mapping, or throws a fatal error.
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
