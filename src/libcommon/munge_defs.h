/*****************************************************************************
 *  $Id: munge_defs.h,v 1.2 2003/04/17 02:14:47 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2002-2003 The Regents of the University of California.
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


#ifndef MUNGE_DEFS_H
#define MUNGE_DEFS_H


#include <munge.h>


/*  Munge credential prefix string.
 */
#define MUNGE_CRED_PREFIX       "MUNGE_"

/*  Munge credential suffix string.
 */
#define MUNGE_CRED_SUFFIX       "_EGNUM"

/*  Current version of the munge credential format.
 */
#define MUNGE_CRED_VERSION      1

/*  Amount of salt (in bytes) encoded into a credential.
 */
#define MUNGE_CRED_SALT_LEN     8

/*  Default munge_cipher_t for encrypting credentials.
 */
#define MUNGE_DEFAULT_CIPHER    MUNGE_CIPHER_CAST5

/*  Default munge_mac_t for validating credentials.
 *  This should NEVER be set to MUNGE_MAC_NONE.
 */
#define MUNGE_DEFAULT_MAC       MUNGE_MAC_SHA1

/*  Default integer for the number of seconds before a credential expires.
 */
#define MUNGE_DEFAULT_TTL       300

/*  Default munge_zip_t for compressing credentials.
 */
#define MUNGE_DEFAULT_ZIP       MUNGE_ZIP_NONE

/*  Integer (uint32_t) sentinel for valid munge message.
 */
#define MUNGE_MSG_MAGIC         0x00606D4B

/*  Current version of the munge client-server message format.
 */
#define MUNGE_MSG_VERSION       1

/*  Socket backlog for the server listening on the unix domain socket.
 */
#define MUNGE_SOCKET_BACKLOG    10

/*  String specifying the unix domain socket pathname for client-server comms.
 */
#define MUNGE_SOCKET_NAME       "/tmp/.munge_socket"

/*  Number of attempts a client makes connecting to the server before failing.
 */
#define MUNGE_SOCKET_RETRIES    5


#endif /* !MUNGE_DEFS_H */
