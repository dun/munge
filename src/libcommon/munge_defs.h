/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2006 The Regents of the University of California.
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


#ifndef MUNGE_DEFS_H
#define MUNGE_DEFS_H

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

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
#if HAVE_EVP_AES_128_CBC
#  define MUNGE_DEFAULT_CIPHER          MUNGE_CIPHER_AES_128
#else  /* !HAVE_EVP_AES_128_CBC */
#  define MUNGE_DEFAULT_CIPHER          MUNGE_CIPHER_CAST5
#endif /* !HAVE_EVP_AES_128_CBC */

/*  Default munge_mac_t for validating credentials.
 *    This should NEVER be set to MUNGE_MAC_NONE.
 */
#define MUNGE_DEFAULT_MAC               MUNGE_MAC_SHA1

/*  Default munge_zip_t for compressing credentials.
 *    Compression incurs a substantial performance penalty.
 *    Typical payloads are too small to achieve any compression.
 */
#define MUNGE_DEFAULT_ZIP               MUNGE_ZIP_NONE

/*  Integer for the default number of seconds before a credential expires.
 */
#define MUNGE_DEFAULT_TTL               300

/*  Integer for the maximum number of seconds before a credential expires.
 */
#define MUNGE_MAXIMUM_TTL               3600

/* Integer for the maximum size (in bytes) of a munge request message.
 */
#define MUNGE_MAXIMUM_REQ_LEN           1048576

/*  Flag to denote that group information comes from "/etc/group".
 *  If set, group information will not be re-parsed unless this file
 *    modification time changes.  If not set, the file modification time
 *    will be ignored and group information will be re-parsed via getgrent()
 *    every time the MUNGE_GROUP_PARSE_TIMER expires.
 */
#define MUNGE_GROUP_STAT_FLAG           1

/*  Integer for the number of seconds between updating group information.
 */
#define MUNGE_GROUP_PARSE_TIMER         900

/*  Flag to allow previously-decoded credentials to be retried.
 *  If the client receives a socket error while communicating with the
 *    server, it will retry the transaction up to MUNGE_SOCKET_XFER_ATTEMPTS.
 *    If such an error occurs after the credential has been inserted into the
 *    replay hash, a subsequent retry will appear as a replayed credential.
 *  If set, a previously-decoded credential will not be marked as being
 *    replayed if the transaction is being retried.
 *  So far, these types of errors have only been seen under linux smp kernels.
 */
#define MUNGE_REPLAY_RETRY_FLAG         1

/*  Integer for the number of seconds between purging the replay hash
 *    of expired credentials.
 */
#define MUNGE_REPLAY_PURGE_TIMER        60

/*  Socket backlog for the server listening on the unix domain socket.
 */
#define MUNGE_SOCKET_BACKLOG            256

/*  String specifying the unix domain socket pathname for client-server comms.
 */
#define MUNGE_SOCKET_NAME               X_LOCALSTATEDIR "/run/munge/munge.socket.2"

/*  Number of attempts a client makes connecting to the server before failing.
 */
#define MUNGE_SOCKET_CONNECT_ATTEMPTS   5

/*  Number of attempts a client makes communicating with the server for a
 *    given credential transaction before failing.
 */
#define MUNGE_SOCKET_XFER_ATTEMPTS      5

/*  Number of microseconds for the start of the linear back-off where the
 *    client sleeps between attempts at retrying a credential transaction.
 *  Ensure (MUNGE_SOCKET_XFER_ATTEMPTS * MUNGE_SOCKET_XFER_USLEEP) < 1e6.
 */
#define MUNGE_SOCKET_XFER_USLEEP        10000

/*  Number of threads to create for processing credential requests.
 */
#define MUNGE_THREADS                   2

/* Flag to allow root to decode any credential regardless of its
 *   UID/GID restrictions.
 */
#define MUNGE_AUTH_ROOT_ALLOW_FLAG      0

/*  The directory in which the pipe used to authenticate a particular client
 *    via fd-passing will be created.
 */
#define MUNGE_AUTH_PIPE_DIR             X_LOCALSTATEDIR "/lib/munge"

/*  The amount of entropy (in bytes) to place in the filename of the pipe used
 *    to authenticate a particular client via fd-passing.
 */
#define MUNGE_AUTH_PIPE_RND_BYTES       16

/*  String specifying the pathname of the daemon's logfile.
 */
#define MUNGED_LOGFILE                  X_LOCALSTATEDIR "/log/munge.log"

/*  String specifying the pathname of the daemon's pidfile.
 */
#define MUNGED_PIDFILE                  X_LOCALSTATEDIR "/run/munge/munged.pid"

/*  String specifying the pathname of the random seed file.
 */
#define MUNGED_RANDOM_SEED              X_LOCALSTATEDIR "/lib/munge/munge.seed"

/*  String specifying the pathname of the secret key file.
 */
#define MUNGED_SECRET_KEY               X_SYSCONFDIR "/munge/munge.key"

/*  String specifying the pathname of the random number source device to use
 *    in case the MUNGED_RANDOM_SEED file contains insufficient entropy.
 */
#define RANDOM_SEED_DEFAULT             "/dev/urandom"


#endif /* !MUNGE_DEFS_H */
