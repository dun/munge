/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2022 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://dun.github.io/munge/>.
 *
 *  MUNGE is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation, either version 3 of the License, or (at your option)
 *  any later version.  Additionally for the MUNGE library (libmunge), you
 *  can redistribute it and/or modify it under the terms of the GNU Lesser
 *  General Public License as published by the Free Software Foundation,
 *  either version 3 of the License, or (at your option) any later version.
 *
 *  MUNGE is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  and GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  and GNU Lesser General Public License along with MUNGE.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#ifndef M_MSG_H
#define M_MSG_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <munge.h>
#include <netinet/in.h>                 /* for struct in_addr                */


/*****************************************************************************
 *  Constants
 *****************************************************************************/

/*  Length of the munge message header (in bytes):
 *    magic + version + type + retry + pkt_len.
 */
#define MUNGE_MSG_HDR_SIZE              11

/*  Sentinel for a valid munge message.
 *    M (13*26^4) + U (21*26^3) + N (14*26^2) + G (7*26^1) + E (5*26^0)
 */
#define MUNGE_MSG_MAGIC                 0x00606D4B

/*  Current version of the munge client-server message format.
 *  This must be incremented whenever the client/server msg format changes;
 *    otherwise, the message may be parsed incorrectly when decoded.
 */
#define MUNGE_MSG_VERSION               4


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

enum m_msg_type {                       /* message type                      */
    MUNGE_MSG_UNDEF,                    /*  undefined (new) message          */
    MUNGE_MSG_HDR,                      /*  message header                   */
    MUNGE_MSG_ENC_REQ,                  /*  encode request message           */
    MUNGE_MSG_ENC_RSP,                  /*  encode response message          */
    MUNGE_MSG_DEC_REQ,                  /*  decode request message           */
    MUNGE_MSG_DEC_RSP,                  /*  decode response message          */
    MUNGE_MSG_AUTH_FD_REQ               /*  auth via fd request message      */
};

struct m_msg {
    int                sd;              /* munge socket descriptor           */
    uint8_t            type;            /* enum m_msg_type                   */
    uint8_t            retry;           /* retry count for this transaction  */
    uint32_t           pkt_len;         /* length of msg pkt mem allocation  */
    void              *pkt;             /* ptr to msg for xfer over socket   */
    uint8_t            cipher;          /* munge_cipher_t enum               */
    uint8_t            mac;             /* munge_mac_t enum                  */
    uint8_t            zip;             /* munge_zip_t enum                  */
    uint8_t            realm_len;       /* length of realm string with NUL   */
    char              *realm_str;       /* security realm string with NUL    */
    uint32_t           ttl;             /* time-to-live                      */
    uint8_t            addr_len;        /* length of IP address              */
    struct in_addr     addr;            /* IP addr where cred was encoded    */
    uint32_t           time0;           /* time at which cred was encoded    */
    uint32_t           time1;           /* time at which cred was decoded    */
    uint32_t           client_uid;      /* UID of connecting client process  */
    uint32_t           client_gid;      /* GID of connecting client process  */
    uint32_t           cred_uid;        /* UID of client that requested cred */
    uint32_t           cred_gid;        /* GID of client that requested cred */
    uint32_t           auth_uid;        /* UID of client allowed to decode   */
    uint32_t           auth_gid;        /* GID of client allowed to decode   */
    uint32_t           data_len;        /* length of data                    */
    void              *data;            /* ptr to data munged into cred      */
    uint32_t           auth_s_len;      /* length of auth srvr string w/ NUL */
    char              *auth_s_str;      /* auth srvr path name string w/ NUL */
    uint32_t           auth_c_len;      /* length of auth clnt string w/ NUL */
    char              *auth_c_str;      /* auth clnt dir name string w/ NUL  */
    uint8_t            error_num;       /* munge_err_t for encode/decode op  */
    uint8_t            error_len;       /* length of err msg str with NUL    */
    char              *error_str;       /* descriptive err msg str with NUL  */
    unsigned           pkt_is_copy:1;   /* true if mem for pkt is a copy     */
    unsigned           realm_is_copy:1; /* true if mem for realm is a copy   */
    unsigned           data_is_copy:1;  /* true if mem for data is a copy    */
    unsigned           error_is_copy:1; /* true if mem for err str is a copy */
    unsigned           auth_s_is_copy:1;/* true if mem for auth srvr is copy */
    unsigned           auth_c_is_copy:1;/* true if mem for auth clnt is copy */
};

typedef struct m_msg *  m_msg_t;
typedef enum m_msg_type m_msg_type_t;
typedef uint32_t        m_msg_magic_t;
typedef uint8_t         m_msg_version_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

munge_err_t m_msg_create (m_msg_t *pm);

void m_msg_destroy (m_msg_t m);

void m_msg_reset (m_msg_t m);

munge_err_t m_msg_bind (m_msg_t m, int sd);

munge_err_t m_msg_send (m_msg_t m, m_msg_type_t type, int maxlen);

munge_err_t m_msg_recv (m_msg_t m, m_msg_type_t type, int maxlen);

int m_msg_set_err (m_msg_t m, munge_err_t e, char *s);


#endif /* !M_MSG_H */
