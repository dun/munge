/*****************************************************************************
 *  $Id: auth_recv.h,v 1.3 2004/11/24 00:21:58 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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


#ifndef MUNGE_AUTH_SERVER_H
#define MUNGE_AUTH_SERVER_H

#include <sys/types.h>
#include "msg.h"


void auth_recv_init (void);
/*
 *  Checks for required privileges needed to perform client authentication.
 */

int auth_recv (msg_t m, uid_t *uid, gid_t *gid);
/*
 *  Receives the identity of the client that sent msg [m],
 *    storing the result in the output parms [uid] and [gid].
 *  Note that the server NEVER simply trusts the client to
 *    directly provide its identity.
 */


#endif /* !MUNGE_AUTH_SERVER_H */
