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


#ifndef CRED_H
#define CRED_H


#include <inttypes.h>
#include <munge.h>
#include "munge_defs.h"
#include "m_msg.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

/*  Current version of the munge credential format.
 */
#define MUNGE_CRED_VERSION              3

#define MAX_DEK                         MUNGE_MAXIMUM_MD_LEN
#define MAX_IV                          MUNGE_MAXIMUM_BLK_LEN
#define MAX_MAC                         MUNGE_MAXIMUM_MD_LEN
#define MAX_SALT                        MUNGE_CRED_SALT_LEN


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct munge_cred {
    uint8_t             version;        /* version of the munge cred format  */
    m_msg_t             msg;            /* ptr to corresponding munge msg    */
    int                 outer_mem_len;  /* length of outer credential memory */
    unsigned char      *outer_mem;      /* outer cred memory allocation      */
    int                 outer_len;      /* length of outer credential data   */
    unsigned char      *outer;          /* ptr to outer credential data      */
    int                 inner_mem_len;  /* length of inner credential memory */
    unsigned char      *inner_mem;      /* inner cred memory allocation      */
    int                 inner_len;      /* length of inner credential data   */
    unsigned char      *inner;          /* ptr to inner credential data      */
    int                 realm_mem_len;  /* length of realm string memory     */
    unsigned char      *realm_mem;      /* realm string memory allocation    */
    int                 salt_len;       /* length of salt data               */
    unsigned char       salt[MAX_SALT]; /* cryptographic seasoning salt      */
    int                 mac_len;        /* length of mac data                */
    unsigned char       mac[MAX_MAC];   /* message authentication code       */
    int                 dek_len;        /* length of dek data                */
    unsigned char       dek[MAX_DEK];   /* symmetric data encryption key     */
    int                 iv_len;         /* length of iv data                 */
    unsigned char       iv[MAX_IV];     /* initialization vector             */
    unsigned char      *outer_zip_ref;  /* ref to zip_t in outer cred memory */
};

typedef struct munge_cred * munge_cred_t;


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_cred_t cred_create (m_msg_t m);

void cred_destroy (munge_cred_t c);


#endif /* !CRED_H */
