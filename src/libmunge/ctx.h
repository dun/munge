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


#ifndef MUNGE_CTX_H
#define MUNGE_CTX_H


#include <netinet/in.h>                 /* for struct in_addr                */
#include <sys/types.h>                  /* for uid_t, gid_t                  */
#include <time.h>                       /* for time_t                        */
#include <munge.h>                      /* for munge_ctx_t, munge_err_t      */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct munge_ctx {
    int                 cipher;         /* symmetric cipher type             */
    int                 mac;            /* message authentication code type  */
    int                 zip;            /* compression type                  */
    char               *realm_str;      /* security realm string with NUL    */
    int                 ttl;            /* time-to-live                      */
    struct in_addr      addr;           /* IP addr where cred was encoded    */
    time_t              time0;          /* time at which cred was encoded    */
    time_t              time1;          /* time at which cred was decoded    */
    uid_t               auth_uid;       /* UID of client allowed to decode   */
    gid_t               auth_gid;       /* GID of client allowed to decode   */
    char               *socket_str;     /* munge domain sock filename w/ NUL */
    munge_err_t         error_num;      /* munge error status                */
    char               *error_str;      /* munge error string with NUL       */
};


/*****************************************************************************
 *  Internal (but still "Extern") Prototypes
 *****************************************************************************/

munge_err_t _munge_ctx_set_err (munge_ctx_t ctx, munge_err_t e, char *s);


#endif /* !MUNGE_CTX_H */
