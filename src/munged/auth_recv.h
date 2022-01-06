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


#ifndef MUNGE_AUTH_RECV_H
#define MUNGE_AUTH_RECV_H


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


#endif /* !MUNGE_AUTH_RECV_H */
