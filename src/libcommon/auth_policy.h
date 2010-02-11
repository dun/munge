/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/


/*****************************************************************************
 *  MUNGE supports the following methods for authenticating the UID and GID
 *    of a client:
 *
 *  MUNGE_AUTH_GETPEEREID (AIX >= 5.2-ML4, Darwin, FreeBSD >= 4.6)
 *    The server uses getpeereid() to determine the identity of the client
 *    connected across the Unix domain socket.
 *
 *  MUNGE_AUTH_GETPEERUCRED (Solaris >= 10)
 *    The server uses getpeerucred() to determine the identity of the client
 *    connected across the Unix domain socket.  The client's UID and GID are
 *    then obtained via ucred_geteuid() and ucred_getegid().
 *
 *  MUNGE_AUTH_PEERCRED (Linux)
 *    The server uses the SO_PEERCRED socket option to determine the identity
 *    of the client connected across the Unix domain socket.  The client's UID
 *    and GID are then obtained from the ucred struct returned by getsockopt().
 *
 *  MUNGE_AUTH_LOCAL_PEERCRED (BSD)
 *    The server uses the LOCAL_PEERCRED socket option to determine the
 *    identity of the client connected across the Unix domain socket.
 *    The client's UID and GID are then obtained from the xucred struct
 *    returned by getsockopt().
 *
 *  MUNGE_AUTH_RECVFD_MKFIFO (Irix, Solaris)
 *    The server creates a unique FIFO special file via mkfifo() and sends a
 *    request to the client for it to pass an open file descriptor back across
 *    this FIFO.  The client creates a unique file and sends the open
 *    descriptor using the I_SENDFD ioctl(), whereby the server receives it
 *    using the I_RECVFD ioctl(). The identity of the client is then obtained
 *    from the strrecvfd struct used to receive the file descriptor.
 *
 *  MUNGE_AUTH_RECVFD_MKNOD (AIX)
 *    The server creates a unique STREAMS-based pipe via mknod() and sends a
 *    request to the client for it to pass an open file descriptor back across
 *    this pipe.  The client creates a unique file and sends the open
 *    descriptor using the I_SENDFD ioctl(), whereby the server receives it
 *    using the I_RECVFD ioctl(). The identity of the client is then obtained
 *    from the strrecvfd struct used to receive the file descriptor. The server
 *    requires root privileges in order to create this pipe.
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

#elif HAVE_GETPEERUCRED && HAVE_UCRED_H
#  define MUNGE_AUTH_GETPEERUCRED

#elif HAVE_SO_PEERCRED
#  define MUNGE_AUTH_PEERCRED

#elif HAVE_STRUCT_XUCRED && HAVE_LOCAL_PEERCRED
#  define MUNGE_AUTH_LOCAL_PEERCRED

#elif HAVE_STRUCT_STRRECVFD && HAVE_FIFO_RECVFD
#  define MUNGE_AUTH_RECVFD_MKFIFO
#  define MUNGE_AUTH_RECVFD

#elif HAVE_STRUCT_STRRECVFD && HAVE__DEV_SPX
#  define MUNGE_AUTH_RECVFD_MKNOD
#  define MUNGE_AUTH_RECVFD

#else
#  error "No support for authenticating the client process."
#endif


#endif /* !MUNGE_AUTH_POLICY_H */
