/*****************************************************************************
 *  $Id: ctx.h,v 1.7 2004/04/03 01:12:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-155910.
 *
 *  Copyright (C) 2002-2004 The Regents of the University of California.
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


#ifndef MUNGE_CTX_H
#define MUNGE_CTX_H


#include <time.h>                       /* for time_t                        */
#include <munge.h>                      /* for munge_ctx_t, munge_err_t      */
#include <netinet/in.h>                 /* for struct in_addr                */
#include "munge_msg.h"                  /* for munge_msg_t                   */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct munge_ctx {
    int                 cipher;         /* symmetric cipher type             */
    int                 zip;            /* compression type                  */
    int                 mac;            /* message authentication code type  */
    char               *realm;          /* security realm                    */
    int                 ttl;            /* time-to-live                      */
    struct in_addr      addr;           /* IP addr where cred was encoded    */
    time_t              time0;          /* time at which cred was encoded    */
    time_t              time1;          /* time at which cred was decoded    */
    char               *socket;         /* munge unix domain socket filename */
    munge_err_t         errnum;         /* munge error status                */
    char               *errstr;         /* munge error string                */
};


/*****************************************************************************
 *  Internal (but still "Extern") Prototypes
 *****************************************************************************/

munge_err_t _munge_ctx_set_err (munge_ctx_t ctx, munge_err_t e, char *s);


#endif /* !MUNGE_CTX_H */
