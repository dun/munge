/*****************************************************************************
 *  $Id: munge.h,v 1.1 2002/12/20 20:30:57 dun Exp $
 *****************************************************************************
 *  Copyright (C) 2002-2003 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-2003-???.
 *
 *  This file is part of Munge, an authentication library.
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Munge is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  Munge is distributed in the hope that it will be useful, but WITHOUT ANY
 *  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with Munge; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************/


#ifndef MUNGE_H
#define MUNGE_H

#include <sys/types.h>


/***********
 *  Notes  *
 ***********/

/*  The magic words are squeamish ossifrage.
 */


/****************
 *  Data Types  *
 ****************/

typedef struct munge_ctx munge_ctx_t;
/*
 *  Munge context opaque data type.
 */

typedef enum {
    EMUNGE_SUCCESS              =  0,
    EMUNGE_SNAFU                = -1,
    EMUNGE_INVAL                = -2,
    EMUNGE_NOMEM                = -3,
    EMUNGE_OVERFLOW             = -4,
    EMUNGE_NO_DAEMON            = -5,
    EMUNGE_BAD_CRED             = -6,
    EMUNGE_BAD_VERSION          = -7,
    EMUNGE_BAD_CIPHER           = -8,
    EMUNGE_BAD_MAC              = -9,
    EMUNGE_CRED_EXPIRED         = -10,
    EMUNGE_CRED_REPLAYED        = -11,
} munge_err_t;


/***************
 *  Functions  *
 ***************/

int munge_encode (char **m, const munge_ctx_t *ctx, const void *buf, int len);
/*
 *  Creates a munged credential contained in a NUL-terminated base64 string.
 *    An optional buffer [buf] of length [len] can be munged in as well.
 *  If the munge context [ctx] is NULL, the default context will be used.
 *  The munged credential is passed back by reference via the [m] parameter;
 *    the caller is responsible for freeing this string.
 *  Returns 0 if the credential is successfully created, or <0 on error.
 */

int munge_decode (const char *m, munge_ctx_t *ctx,
                  void *buf, int *len, uid_t *uid, gid_t *gid);
/*
 *  Validates the NUL-terminated munged credential [m].
 *  If [ctx] is not NULL, it will be set to the munge context used to
 *    encode the credential.
 *  If [buf] is not NULL, then [len] must first be set to the size of [buf].
 *    Then if any optional data was munged into the credential, up to [len]
 *    bytes of it will be copied into [buf], and [len] will be set to the
 *    total size of this data.  If the return value of [len] is greater than
 *    its initial value, the [buf] data has been truncated.
 *  If [uid] or [gid] is not NULL, they will be set to the UID/GID
 *    of the process that created the credential.
 *  Returns 0 if the credential is valid, or <0 on error.
 */

const char * munge_strerror (munge_err_t errnum);
/*
 *  Returns a descriptive string for the munge error [errnum],
 *    or an unknown error message if the error code is unknown.
 */


#endif /* !MUNGE_H */
