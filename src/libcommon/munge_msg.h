/*****************************************************************************
 *  $Id: munge_msg.h,v 1.8 2004/01/29 19:09:11 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
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


#ifndef MUNGE_MSG_H
#define MUNGE_MSG_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <munge.h>
#include <netinet/in.h>                 /* for struct in_addr                */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

/*  The munge_msg_v1 struct is used to handle data passed over the domain
 *    socket between client (libmunge) and server (munged), as well as data
 *    for the credential itself.  This seemed like a good idea at the time,
 *    but has caused some confusion since the data representation differs
 *    slightly in both cases.
 *  In particular, the realm string and error string passed over the domain
 *    socket are both NUL-terminated in addition to carrying a string length
 *    (which includes the NUL character).
 *  In contrast, the realm string packed inside the credential is not
 *    NUL-terminated; instead, it is represented as a length followed by an
 *    unterminated string.  This saved space in the credential (since the
 *    NUL would have been redundant) and allowed for quicker unpacking.  
 */

enum munge_type {                       /* message type                      */
    MUNGE_MSG_UNKNOWN,                  /*  uninitialized message            */
    MUNGE_MSG_ENC_REQ,                  /*  encode request message           */
    MUNGE_MSG_ENC_RSP,                  /*  encode response message          */
    MUNGE_MSG_DEC_REQ,                  /*  decode request message           */
    MUNGE_MSG_DEC_RSP,                  /*  decode response message          */
    MUNGE_MSG_LAST_ENTRY
};

struct munge_msg_head {
    uint32_t                magic;      /* eye of newt and toe of frog       */
    uint8_t                 version;    /* message version                   */
    uint8_t                 type;       /* enum munge_type                   */
    uint32_t                length;     /* length of msg body                */
};

struct munge_msg_v1 {
    uint8_t                 cipher;     /* munge_cipher_t enum               */
    uint8_t                 zip;        /* munge_zip_t enum                  */
    uint8_t                 mac;        /* munge_mac_t enum                  */
    uint8_t                 realm_len;  /* length of realm string            */
    char                   *realm;      /* security realm string             */
    uint32_t                ttl;        /* time-to-live                      */
    uint8_t                 addr_len;   /* length of IP address              */
    struct in_addr          addr;       /* IP addr where cred was encoded    */
    uint32_t                time0;      /* time at which cred was encoded    */
    uint32_t                time1;      /* time at which cred was decoded    */
    uint32_t                uid;        /* client process UID encoding cred  */
    uint32_t                gid;        /* client process GID encoding cred  */
    uint32_t                data_len;   /* length of data                    */
    void                   *data;       /* ptr to data munged into cred      */
    uint8_t                 error_num;  /* munge_err_t for encode/decode op  */
    uint8_t                 error_len;  /* length of err msg str with NUL    */
    char                   *error_str;  /* NUL-term'd descriptive errmsg str */
};

struct munge_msg {
    int                     sd;         /* munge socket descriptor           */
    struct munge_msg_head   head;       /* message header                    */
    int                     pbody_len;  /* length of msg body mem allocation */
    void                   *pbody;      /* ptr to msg body based on version  */
    munge_err_t             errnum;     /* munge error status code           */
    char                   *errstr;     /* munge NUL-term'd error string     */
};

typedef struct munge_msg * munge_msg_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

munge_err_t _munge_msg_create (munge_msg_t *pm, int sd);

void _munge_msg_destroy (munge_msg_t m);

munge_err_t _munge_msg_send (munge_msg_t m);

munge_err_t _munge_msg_recv (munge_msg_t m);

munge_err_t _munge_msg_reset (munge_msg_t m);

int _munge_msg_set_err (munge_msg_t m, munge_err_t e, char *s);



#endif /* !MUNGE_MSG_H */
