/*****************************************************************************
 *  $Id: auth_policy.h,v 1.2 2004/05/14 00:47:59 dun Exp $
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


/*****************************************************************************
 *  Munge supports the following types of client authentication:
 *
 *  MUNGE_AUTH_GETPEEREID (FreeBSD)
 *  - The server uses the getpeereid() call to determine the identity of the
 *    client connected to the unix domain socket.
 *
 *  MUNGE_AUTH_PEERCRED (Linux)
 *  - The server uses the SO_PEERCRED socket option to determine the identity
 *    of the client connected to the unix domain socket.
 *
 *  MUNGE_AUTH_RECVFD_MKFIFO (Irix, Solaris)
 *  - The server creates a unique FIFO special file and sends a request to
 *    the client to use it for sending a file descriptor back across.  The fd
 *    is sent by the client using the I_SENDFD ioctl(), and received by the
 *    server using the I_RECVFD ioctl().  The identity of the client is then
 *    obtained from the strrecvfd struct used to receive the fd.
 *
 *  MUNGE_AUTH_RECVFD_MKNOD (AIX)
 *  - The server creates a unique STREAMS-based pipe and sends a request to
 *    the client to use it for sending a file descriptor back across.  The fd
 *    is sent by the client using the I_SENDFD ioctl(), and received by the
 *    server using the I_RECVFD ioctl().  The identity of the client is then
 *    obtained from the strrecvfd struct used to receive the fd.  Root
 *    privileges are required by the server to create the pipe.
 *
 *****************************************************************************/


#ifndef MUNGE_AUTH_POLICY_H
#define MUNGE_AUTH_POLICY_H

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */


#if   HAVE_GETPEEREID
#  define MUNGE_AUTH_GETPEEREID

#elif HAVE_SO_PEERCRED
#  define MUNGE_AUTH_PEERCRED

#elif HAVE_STRUCT_STRRECVFD && HAVE_FIFO_RECVFD
#  define MUNGE_AUTH_RECVFD_MKFIFO

#elif HAVE_STRUCT_STRRECVFD && HAVE__DEV_SPX
#  define MUNGE_AUTH_RECVFD_MKNOD

#else
#  error "No support for authenticating the client process."
#endif

#if defined (MUNGE_AUTH_RECVFD_MKFIFO) || defined (MUNGE_AUTH_RECVFD_MKNOD)
#  define MUNGE_AUTH_RECVFD_COMMON
#endif /* MUNGE_AUTH_RECVFD_COMMON */


/*  The amount of entropy (in bytes) to place in the filename of the pipe used
 *    to authenticate a particular client via fd-passing.
 */
#define AUTH_PIPE_NAME_RND_BYTES        8

/*  The maximum string length for the filename of the pipe used to
 *    authenticate a particular client via fd-passing.
 *  The auth pipe name is of the form "PREFIX/.munge-RANDOM.pipe":
 *    (strlen (AUTH_PIPE_NAME_PREFIX) + (AUTH_PIPE_NAME_RND_BYTES * 2) + 14).
 */
#define AUTH_PIPE_NAME_MAX_LEN          (4 +(AUTH_PIPE_NAME_RND_BYTES *2) +14)

/*  The directory prefix for the pipe used to authenticate a particular client
 *    via fd-passing.
 *  Update AUTH_PIPE_NAME_MAX_LEN accordingly.
 */
#define AUTH_PIPE_NAME_PREFIX           "/tmp"


#endif /* !MUNGE_AUTH_POLICY_H */
