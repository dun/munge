/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2005 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <munge.h>
#include <openssl/evp.h>
#include "lookup.h"


const EVP_CIPHER *
lookup_cipher (munge_cipher_t cipher)
{
    switch (cipher) {
        case MUNGE_CIPHER_BLOWFISH:
            return (EVP_bf_cbc ());
        case MUNGE_CIPHER_CAST5:
            return (EVP_cast5_cbc ());
#if HAVE_EVP_AES_128_CBC
        case MUNGE_CIPHER_AES_128:
            return (EVP_aes_128_cbc ());
#endif /* HAVE_EVP_AES_128_CBC */
        default:
            break;
    }
    return (NULL);
}


const EVP_MD *
lookup_mac (munge_mac_t mac)
{
    switch (mac) {
        case MUNGE_MAC_MD5:
            return (EVP_md5 ());
        case MUNGE_MAC_SHA1:
            return (EVP_sha1 ());
        case MUNGE_MAC_RIPEMD160:
            return (EVP_ripemd160 ());
        default:
            break;
    }
    return (NULL);
}
