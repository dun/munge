/*****************************************************************************
 *  $Id: strings.c,v 1.5 2004/04/03 21:53:00 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2002-2004 The Regents of the University of California.
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


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <munge.h>
#include "common.h"


/*****************************************************************************
 *  Munge Strings
 *****************************************************************************/

/*  Keep in sync with munge_cipher_t enum.
 */
const char * munge_cipher_strings[] = {
    "none",
    "default",
    "blowfish",
    "cast5",
#if HAVE_EVP_AES_128_CBC
    "aes128",
#else  /* !HAVE_EVP_AES_128_CBC */
    "",
#endif /* !HAVE_EVP_AES_128_CBC */
     NULL
};

/*  Keep in sync with munge_mac_t enum.
 */
const char * munge_mac_strings[] = {
    "",
    "default",
    "md5",
    "sha1",
    "ripemd160",
     NULL
};

/*  Keep in sync with munge_zip_t enum.
 */
const char * munge_zip_strings[] = {
    "none",
    "default",
#if HAVE_PKG_BZLIB
    "bzlib",
#else  /* !HAVE_PKG_BZLIB */
    "",
#endif /* !HAVE_PKG_BZLIB */
#if HAVE_PKG_ZLIB
    "zlib",
#else  /* !HAVE_PKG_ZLIB */
    "",
#endif /* HAVE_PKG_ZLIB */
     NULL
};
