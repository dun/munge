/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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


#ifndef CRED_H
#define CRED_H


#include <inttypes.h>
#include <openssl/evp.h>
#include "munge_defs.h"
#include "m_msg.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

/*  Current version of the munge credential format.
 */
#define MUNGE_CRED_VERSION              2

/*  MAX_MAC is currently set to 20 (ie, 160 bits).  This handles the largest
 *    message digests supported by munge_mac_t.  Note, however, <openssl/evp.h>
 *    defines EVP_MAX_MD_SIZE which is currently set to (16+20) to handle the
 *    SSLv3 md5+sha1 type.  But since MUNGE doesn't support that type, setting
 *    MAX_MAC at 20 reduces the memory requirements for data structures such as
 *    the replay hash.
 */
#define MAX_DEK                         EVP_MAX_KEY_LENGTH
#define MAX_IV                          EVP_MAX_IV_LENGTH
#define MAX_MAC                         20
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
    int                 zippy_mem_len;  /* length of inner compressed memory */
    unsigned char      *zippy_mem;      /* inner compressed mem allocation   */
    int                 zippy_len;      /* length of inner compressed data   */
    unsigned char      *zippy;          /* ptr to inner compressed data      */
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
