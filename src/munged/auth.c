/*****************************************************************************
 *  $Id: auth.c,v 1.3 2004/04/03 01:12:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-155910.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>

#if HAVE_GETPEEREID
#  include <unistd.h>
#elif HAVE_SO_PEERCRED
#  include <sys/socket.h>
#endif


/*  FIXME: Add autoconf support for socklen_t.
 */


int
auth_peer_get (int sd, uid_t *uid, gid_t *gid)
{
#if HAVE_GETPEEREID

    return (getpeereid (sd, uid, gid));

#elif HAVE_SO_PEERCRED

    struct ucred cred;
    socklen_t len = sizeof (cred);

    if (getsockopt (sd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
        return (-1);
    *uid = cred.uid;
    *gid = cred.gid;

#else

#error "No support for authenticating a non-parent process."

#endif

    return (0);
}
