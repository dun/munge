/*****************************************************************************
 *  $Id: munge.h,v 1.3 2003/02/13 17:55:58 dun Exp $
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


#ifndef MUNGE_H
#define MUNGE_H

#include <sys/types.h>


/***********
 *  Notes  *
 ***********/


/****************
 *  Data Types  *
 ****************/

typedef struct munge_ctx munge_ctx_t;

/*  NOTE: Error codes must be in the range [1..255] in order to
 *        provide a meaningful return status when returned via exit().
 */
typedef enum {
    EMUNGE_SUCCESS              = 0,    /* Whoohoo! */
    EMUNGE_SNAFU                = 1,    /* Doh! */
    EMUNGE_INVAL                = 2,    /* Invalid argument */
    EMUNGE_NOMEM                = 3,    /* Out of memory */
    EMUNGE_OVERFLOW             = 4,    /* Buffer overflow */
    EMUNGE_NO_DAEMON            = 5,    /* Munged not found */
    EMUNGE_TIMEOUT              = 6,    /* Munged timeout */
    EMUNGE_PROTO                = 7,    /* Munged protocol error */
    EMUNGE_BAD_CRED             = 8,    /* Bad credential (generic) */
    EMUNGE_BAD_VERSION          = 9,    /* Bad credential version */
    EMUNGE_BAD_CIPHER           = 10,   /* Bad credential cipher type */
    EMUNGE_BAD_ZIP              = 11,   /* Bad credential compression type */
    EMUNGE_BAD_MAC              = 12,   /* Bad credential MAC type */
    EMUNGE_CRED_EXPIRED         = 13,   /* Credential expired */
    EMUNGE_CRED_PREMATURE       = 14,   /* Credential has future creation */
    EMUNGE_CRED_REPLAYED        = 15    /* Credential replayed */
} munge_err_t;


/***************
 *  Functions  *
 ***************/

munge_err_t munge_encode (char **m, const munge_ctx_t *ctx,
                          const void *buf, int len);
/*
 *  Creates a munged credential contained in a NUL-terminated base64 string.
 *    An optional buffer [buf] of length [len] can be munged in as well.
 *  If the munge context [ctx] is NULL, the default context will be used.
 *  The munged credential is passed back by reference via the [m] parameter;
 *    the caller is responsible for freeing this string.
 *  Returns EMUNGE_SUCCESS if the credential is successfully created;
 *    o/w, sets [m] to NULL and returns the munge error number.
 */

munge_err_t munge_decode (const char *m, munge_ctx_t *ctx,
                          void **buf, int *len, uid_t *uid, gid_t *gid);
/*
 *  Validates the NUL-terminated munged credential [m].
 *  If [ctx] is not NULL, it will be set to the munge context used to
 *    encode the credential.
 *  If [buf] and [len] are not NULL, [buf] will be set to the optional
 *    data munged into the credential and [len] will be set to its length.
 *    The caller is responsible for freeing the memory referenced by [buf].
 *    If no data was munged into the credential or an error is encountered,
 *    [buf] will be set to NULL and [len] will be set to 0.
 *  If [uid] or [gid] is not NULL, they will be set to the UID/GID
 *    of the process that created the credential.
 *  Returns EMUNGE_SUCCESS if the credential is valid; o/w, returns the
 *    munge error number.
 */

const char * munge_strerror (munge_err_t e);
/*
 *  Returns a descriptive string for the munge errno [e].
 */


#endif /* !MUNGE_H */
