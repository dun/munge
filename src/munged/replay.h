/*****************************************************************************
 *  $Id: replay.h,v 1.1 2003/11/26 23:07:49 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
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


#ifndef REPLAY_H
#define REPLAY_H


#include "cred.h"


/*****************************************************************************
 *  Public Constants
 *****************************************************************************/

#define REPLAY_HASH_SIZE        4013


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void replay_init (void);

void replay_fini (void);

int replay_insert (munge_cred_t c);

void replay_purge (void);


#endif /* !REPLAY_H */
