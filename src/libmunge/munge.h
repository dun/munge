/*****************************************************************************
 *  $Id: munge.h,v 1.12 2003/05/02 16:44:06 dun Exp $
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


/*****************************************************************************
 *  Got GPL?
 *****************************************************************************/

#if ! GPL_LICENSED
  #error By linking against libmunge, the derivative
  #error work becomes licensed under the terms of the
  #error GNU General Public License.  Acknowledge by
  #error defining the GPL_LICENSED preprocessor macro.
#endif /* !GPL_LICENSED */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

/*  Munge context opaque data type
 */
typedef struct munge_ctx * munge_ctx_t;

/*  Munge context options
 */
typedef enum munge_opt {
    MUNGE_OPT_CIPHER_TYPE       =  0,   /* symmetric cipher type (int)       */
    MUNGE_OPT_MAC_TYPE          =  1,   /* message auth code type (int)      */
    MUNGE_OPT_ZIP_TYPE          =  2,   /* compression type (int)            */
    MUNGE_OPT_REALM             =  3,   /* security realm (str)              */
    MUNGE_OPT_TTL               =  4,   /* time-to-live (int)                */
    MUNGE_OPT_ENCODE_TIME       =  5,   /* time when cred encoded (time_t)   */
    MUNGE_OPT_DECODE_TIME       =  6,   /* time when cred decoded (time_t)   */
    MUNGE_OPT_SOCKET            =  7,   /* socket for comm w/ daemon (str)   */
    MUNGE_OPT_LAST_ENTRY
} munge_opt_t;

/*  Munge symmetric cipher types
 */
typedef enum munge_cipher {
    MUNGE_CIPHER_NONE           =  0,   /* encryption disabled               */
    MUNGE_CIPHER_DEFAULT        =  1,   /* default ciphr specified by daemon */
    MUNGE_CIPHER_BLOWFISH       =  2,   /* Blowfish CBC w/ 64b-blk/128b-key  */
    MUNGE_CIPHER_CAST5          =  3,   /* CAST5 CBC w/ 64b-blk/128b-key     */
    MUNGE_CIPHER_AES_128        =  4,   /* AES CBC w/ 128b-blk/128b-key      */
    MUNGE_CIPHER_LAST_ENTRY
} munge_cipher_t;

/*  Munge message authentication code types
 */
typedef enum munge_mac {
    MUNGE_MAC_NONE              =  0,   /* mac disabled -- invalid, btw      */
    MUNGE_MAC_DEFAULT           =  1,   /* default mac specified by daemon   */
    MUNGE_MAC_MD5               =  2,   /* MD5 w/ 128b-digest                */
    MUNGE_MAC_SHA1              =  3,   /* SHA-1 w/ 160b-digest              */
    MUNGE_MAC_RIPEMD160         =  4,   /* RIPEMD-160 w/ 160b-digest         */
    MUNGE_MAC_LAST_ENTRY
} munge_mac_t;

/*  Munge compression types
 */
typedef enum munge_zip {
    MUNGE_ZIP_NONE              =  0,   /* compression disabled              */
    MUNGE_ZIP_DEFAULT           =  1,   /* default zip specified by daemon   */
    MUNGE_ZIP_LAST_ENTRY
} munge_zip_t;

/*  Munge credential time-to-live (in seconds)
 */
typedef enum munge_ttl {
    MUNGE_TTL_FOREVER           = -1,   /* credential never expires          */
    MUNGE_TTL_DEFAULT           =  0,   /* default ttl specified by daemon   */
    MUNGE_TTL_LAST_ENTRY
} munge_ttl_t;

/*  Munge error codes
 *
 *  XXX: Error codes must be in the range [1..255] in order to
 *       provide a meaningful return status when returned via exit().
 */
typedef enum munge_err {
    EMUNGE_SUCCESS              =  0,   /* Whoohoo!                          */
    EMUNGE_SNAFU                =  1,   /* Doh!                              */
    EMUNGE_BAD_ARG              =  2,   /* Invalid argument                  */
    EMUNGE_OVERFLOW             =  3,   /* Buffer overflow                   */
    EMUNGE_NO_MEMORY            =  4,   /* Out of memory                     */
    EMUNGE_NO_DAEMON            =  5,   /* Munged not found                  */
    EMUNGE_SOCKET               =  6,   /* Munged communication error        */
    EMUNGE_TIMEOUT              =  7,   /* Munged timeout                    */
    EMUNGE_BAD_CRED             =  8,   /* Bad credential format             */
    EMUNGE_BAD_VERSION          =  9,   /* Bad credential version            */
    EMUNGE_BAD_CIPHER           = 10,   /* Bad credential cipher type        */
    EMUNGE_BAD_ZIP              = 11,   /* Bad credential compression type   */
    EMUNGE_BAD_MAC              = 12,   /* Bad credential msg auth code type */
    EMUNGE_BAD_REALM            = 13,   /* Bad credential security realm     */
    EMUNGE_CRED_INVALID         = 14,   /* Credential invalid                */
    EMUNGE_CRED_EXPIRED         = 15,   /* Credential expired                */
    EMUNGE_CRED_REWOUND         = 16,   /* Credential created in the future  */
    EMUNGE_CRED_REPLAYED        = 17,   /* Credential replayed               */
    EMUNGE_LAST_ENTRY
} munge_err_t;


/*****************************************************************************
 *  Extern Variables
 *****************************************************************************/

/*  NULL-terminated array of descriptive strings for the munge_cipher_t.
 */
extern const char * munge_cipher_strings[];

/*  NULL-terminated array of descriptive strings for the munge_mac_t.
 */
extern const char * munge_mac_strings[];

/*  NULL-terminated array of descriptive strings for the munge_zip_t.
 */
extern const char * munge_zip_strings[];


/*****************************************************************************
 *  Primary Functions
 *****************************************************************************/

munge_err_t munge_encode (char **cred, munge_ctx_t ctx,
                          const void *buf, int len);
/*
 *  Creates a munged credential contained in a NUL-terminated base64 string.
 *    An optional buffer [buf] of length [len] can be munged in as well.
 *  If the munge context [ctx] is NULL, the default context will be used.
 *  The munged credential is passed back by reference via the [cred] parameter;
 *    the caller is responsible for freeing this string.
 *  Returns EMUNGE_SUCCESS if the credential is successfully created;
 *    o/w, sets [cred] to NULL and returns the munge error number.
 */

munge_err_t munge_decode (const char *cred, munge_ctx_t ctx,
                          void **buf, int *len, uid_t *uid, gid_t *gid);
/*
 *  Validates the NUL-terminated munged credential [cred].
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
 *  Returns a descriptive string describing the munge errno [e].
 */


/*****************************************************************************
 *  Context Functions
 *****************************************************************************/

munge_ctx_t munge_ctx_create (void);
/*
 *  Creates and returns a new munge context, or NULL on error (out-of-memory).
 *  Abandoning a context without calling munge_ctx_destroy() will result
 *    in a memory leak.
 */

void munge_ctx_destroy (munge_ctx_t ctx);
/*
 *  Destroys the context [ctx].
 */

const char * munge_ctx_strerror (munge_ctx_t ctx);
/*
 *  Returns the error message associated with the last munge operation in
 *    which the context [ctx] was passed, or NULL if no error condition exists.
 *  This message may be more detailed than that returned by munge_strerror().
 *  If a context is supplied to munge_encode(), munge_decode(),
 *    munge_ctx_get(), or munge_ctx_set(), the error status and
 *    error message will be updated as appropriate.
 */

munge_err_t munge_ctx_get (munge_ctx_t ctx, munge_opt_t opt, ...);
/*
 *  Gets the option [opt] from the context [ctx] and stores the result
 *    in the following ptr argument(s).  Refer to the munge_opt_t enum
 *    comments for argument types.  In the case of a string, it sets the
 *    (char **) to the actual internal string, not a copy -- remember,
 *    it's not your string, you're just borrowing it.
 *  Returns EMUNGE_SUCCESS on success; o/w, returns the munge error number.
 */

munge_err_t munge_ctx_set (munge_ctx_t ctx, munge_opt_t opt, ...);
/*
 *  Sets the option [opt] for the context [ctx] from the following argument(s).
 *    Refer to the munge_opt_t enum comments for argument types.
 *  Returns EMUNGE_SUCCESS on success; o/w, returns the munge error number.
 */


#endif /* !MUNGE_H */
