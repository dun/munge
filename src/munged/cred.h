/*****************************************************************************
 *  $Id: cred.h,v 1.1 2003/04/08 18:16:16 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
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


#ifndef CRED_H
#define CRED_H


#if HAVE_STDINT_H
#  include <stdint.h>
#endif /* HAVE_STDINT_H */

#include <openssl/evp.h>
#include "munge_defs.h"
#include "munge_msg.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MAX_DEK         EVP_MAX_KEY_LENGTH
#define MAX_IV          EVP_MAX_IV_LENGTH
#define MAX_MAC         EVP_MAX_MD_SIZE
#define MAX_SALT        MUNGE_CRED_SALT_LEN


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct munge_cred {
    uint8_t             version;        /* version of the munge cred format  */
    munge_msg_t         msg;            /* ptr to corresponding munge msg    */
    int                 cred_len;       /* length of munged credential       */
    unsigned char      *cred;           /* munged credential                 */
    int                 outer_len;      /* length of outer credential data   */
    unsigned char      *outer;          /* outer cred data w/o crypto xforms */
    int                 inner_len;      /* length of inner credential data   */
    unsigned char      *inner;          /* inner cred data w/ crypto xforms  */
    int                 salt_len;       /* length of salt data               */
    unsigned char       salt[MAX_SALT]; /* cryptographic seasoning salt      */
    int                 mac_len;        /* length of mac data                */
    unsigned char       mac[MAX_MAC];   /* message authentication code       */
    int                 dek_len;        /* length of dek data                */
    unsigned char       dek[MAX_DEK];   /* symmetric data encryption key     */
    int                 iv_len;         /* length of iv data                 */
    unsigned char       iv[MAX_IV];     /* initialization vector             */
};

typedef struct munge_cred * munge_cred_t;


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_cred_t cred_create (munge_msg_t m);

void cred_destroy (munge_cred_t c);


#endif /* !CRED_H */
