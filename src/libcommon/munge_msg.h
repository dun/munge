/*****************************************************************************
 *  $Id: munge_msg.h,v 1.3 2003/04/22 20:49:35 dun Exp $
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


#ifndef MUNGE_MSG_H
#define MUNGE_MSG_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#if HAVE_STDINT_H
#  include <stdint.h>
#endif /* HAVE_STDING_H */

#include <munge.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

enum munge_type {                       /* message type                      */
    MUNGE_MSG_UNKNOWN,                  /*  uninitialized message            */
    MUNGE_MSG_ERROR,                    /*  error message                    */
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
    uint8_t                 errnum;     /* munge_err_t for encode/decode op  */
    uint8_t                 cipher;     /* munge_cipher_t enum               */
    uint8_t                 zip;        /* munge_zip_t enum                  */
    uint8_t                 mac;        /* munge_mac_t enum                  */
    uint8_t                 realm_len;  /* length of realm string            */
    char                   *realm;      /* security realm string             */
    uint32_t                ttl;        /* time-to-live                      */
    uint32_t                time0;      /* time at which cred was encoded    */
    uint32_t                time1;      /* time at which cred was decoded    */
    uint32_t                uid;        /* client process UID encoding cred  */
    uint32_t                gid;        /* client process GID encoding cred  */
    uint32_t                data_len;   /* length of data                    */
    void                   *data;       /* ptr to data munged into cred      */
};

struct munge_msg {
    int                     sd;         /* munge socket descriptor           */
    struct munge_msg_head   head;       /* message header                    */
    int                     pbody_len;  /* length of msg body mem allocation */
    void                   *pbody;      /* ptr to msg body based on version  */
    munge_err_t             status;     /* munge status code                 */
    char                   *errstr;     /* munge error string                */
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

char * _munge_msg_get_err (munge_msg_t m);

int _munge_msg_set_err (munge_msg_t m, munge_err_t e, const char *str);



#endif /* !MUNGE_MSG_H */
