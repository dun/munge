/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2007 The Regents of the University of California.
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


#ifndef MUNGE_AUTH_SERVER_H
#define MUNGE_AUTH_SERVER_H


#include <sys/types.h>
#include "m_msg.h"


void auth_recv_init (const char *srvrdir, const char *clntdir, int got_force);
/*
 *  Checks for required privileges needed to perform client authentication.
 */

int auth_recv (m_msg_t m, uid_t *uid, gid_t *gid);
/*
 *  Receives the identity of the client that sent msg [m],
 *    storing the result in the output parms [uid] and [gid].
 *  Note that the server NEVER simply trusts the client to
 *    directly provide its identity.
 */


#endif /* !MUNGE_AUTH_SERVER_H */
