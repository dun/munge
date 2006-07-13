/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2004-2006 The Regents of the University of California.
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


/*****************************************************************************
 *  Client authentication type
 *****************************************************************************/

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


#endif /* !MUNGE_AUTH_POLICY_H */
