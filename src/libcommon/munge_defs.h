/*****************************************************************************
 *  $Id: munge_defs.h,v 1.23 2004/05/06 01:41:12 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2002-2004 The Regents of the University of California.
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


#ifndef MUNGE_DEFS_H
#define MUNGE_DEFS_H


#include <munge.h>


/*  Munge credential prefix string.
 */
#define MUNGE_CRED_PREFIX               "MUNGE:"

/*  Munge credential suffix string.
 */
#define MUNGE_CRED_SUFFIX               ":"

/*  Amount of salt (in bytes) encoded into a credential.
 */
#define MUNGE_CRED_SALT_LEN             8

/*  Default munge_cipher_t for encrypting credentials.
 */
#define MUNGE_DEFAULT_CIPHER            MUNGE_CIPHER_CAST5

/*  Default munge_mac_t for validating credentials.
 *    This should NEVER be set to MUNGE_MAC_NONE.
 */
#define MUNGE_DEFAULT_MAC               MUNGE_MAC_SHA1

/*  Default munge_zip_t for compressing credentials.
 */
#define MUNGE_DEFAULT_ZIP               MUNGE_ZIP_ZLIB

/*  Integer for the default number of seconds before a credential expires.
 */
#define MUNGE_DEFAULT_TTL               300

/*  Integer for the maximum number of seconds before a credential expires.
 */
#define MUNGE_MAXIMUM_TTL               3600

/*  Integer for the number of seconds between purging the replay hash
 *    of expired creds.
 */
#define MUNGE_REPLAY_PURGE_TIMER        300

/*  Integer (uint32_t) sentinel for valid munge message.
 */
#define MUNGE_MSG_MAGIC                 0x00606D4B

/*  Socket backlog for the server listening on the unix domain socket.
 */
#define MUNGE_SOCKET_BACKLOG            256

/*  String specifying the unix domain socket pathname for client-server comms.
 */
#define MUNGE_SOCKET_NAME               "/tmp/.munge-sock"

/*  Number of attempts a client makes connecting to the server before failing.
 */
#define MUNGE_SOCKET_CONNECT_RETRIES    5

/*  String specifying the pathname of the daemon's logfile.
 *    FIXME: Temporary kludge until configuration file support is added.
 */
#define MUNGED_LOGFILE                  "/tmp/.munge-log"

/*  String specifying the pathname of the random seed file.
 *    FIXME: Temporary kludge until configuration file support is added.
 */
#define MUNGED_RANDOM_SEED              "/tmp/.munge-seed"

/*  String specifying the pathname of the secret key file.
 *    FIXME: Temporary kludge until configuration file support is added.
 */
/* #define MUNGED_SECRET_KEY               "/tmp/.munge-key"
 */
#define MUNGED_SECRET_KEY               "/etc/ssh/ssh_host_key"

/*  String specifying the pathname of the random number source device to use
 *    in case the MUNGED_RANDOM_SEED file contains insufficient entropy.
 */
#define RANDOM_SEED_DEFAULT             "/dev/urandom"


#endif /* !MUNGE_DEFS_H */
