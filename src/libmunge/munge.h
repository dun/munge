/*****************************************************************************
 *  $Id: munge.h,v 1.25 2004/11/18 00:48:13 dun Exp $
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


#ifndef MUNGE_H
#define MUNGE_H

#include <sys/types.h>


/*****************************************************************************
 *  Got GPL?
 *****************************************************************************/

#if ! GPL_LICENSED
#  error By linking against libmunge, the derivative
#  error work becomes licensed under the terms of the
#  error GNU General Public License.  Acknowledge by
#  error defining the GPL_LICENSED preprocessor macro.
#endif /* !GPL_LICENSED */


/*****************************************************************************
 *  Got C++?
 *****************************************************************************/

#undef BEGIN_C_DECLS
#undef END_C_DECLS
#ifdef __cplusplus
#  define BEGIN_C_DECLS         extern "C" {
#  define END_C_DECLS           }
#else  /* !__cplusplus */
#  define BEGIN_C_DECLS         /* empty */
#  define END_C_DECLS           /* empty */
#endif /* !__cplusplus */


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
    MUNGE_OPT_ADDR4             =  5,   /* src IPv4 addr (struct in_addr)    */
    MUNGE_OPT_ENCODE_TIME       =  6,   /* time when cred encoded (time_t)   */
    MUNGE_OPT_DECODE_TIME       =  7,   /* time when cred decoded (time_t)   */
    MUNGE_OPT_SOCKET            =  8,   /* socket for comm w/ daemon (str)   */
    MUNGE_OPT_UID_RESTRICTION   =  9,   /* UID able to decode cred (uid_t)   */
    MUNGE_OPT_GID_RESTRICTION   = 10,   /* GID able to decode cred (gid_t)   */
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
    MUNGE_ZIP_BZLIB             =  2,   /* bzip2 by Julian Seward            */
    MUNGE_ZIP_ZLIB              =  3,   /* zlib "deflate" by Gailly & Adler  */
    MUNGE_ZIP_LAST_ENTRY
} munge_zip_t;

/*  Munge credential time-to-live (in seconds)
 */
typedef enum munge_ttl {
    MUNGE_TTL_MAXIMUM           = -1,   /* maximum ttl allowed by daemon     */
    MUNGE_TTL_DEFAULT           =  0    /* default ttl specified by daemon   */
} munge_ttl_t;

/*  Munge UID restrictions for credential decoding
 */
typedef enum munge_uid {
    MUNGE_UID_ANY               = -1    /* do not restrict decode via uid    */
} munge_uid_t;

/*  Munge GID restrictions for credential decoding
 */
typedef enum munge_gid {
    MUNGE_GID_ANY               = -1    /* do not restrict decode via gid    */
} munge_gid_t;

/*  Munge enum types for str/int conversions
 */
typedef enum munge_enum {
    MUNGE_ENUM_CIPHER           =  0,   /* cipher enum type                  */
    MUNGE_ENUM_MAC              =  1,   /* mac enum type                     */
    MUNGE_ENUM_ZIP              =  2    /* zip enum type                     */
} munge_enum_t;

/*  Munge error codes
 *
 *  XXX: Error codes must be in the range [1..255] in order to
 *       provide a meaningful return status when returned via exit().
 */
typedef enum munge_err {
    EMUNGE_SUCCESS              =  0,   /* Whoohoo!                          */
    EMUNGE_SNAFU                =  1,   /* Doh!                              */
    EMUNGE_BAD_ARG              =  2,   /* Invalid argument                  */
    EMUNGE_BAD_LENGTH           =  3,   /* Exceeded maximum message length   */
    EMUNGE_OVERFLOW             =  4,   /* Buffer overflow                   */
    EMUNGE_NO_MEMORY            =  5,   /* Out of memory                     */
    EMUNGE_NO_DAEMON            =  6,   /* Munged not found                  */
    EMUNGE_SOCKET               =  7,   /* Munged communication error        */
    EMUNGE_TIMEOUT              =  8,   /* Munged timeout                    */
    EMUNGE_BAD_CRED             =  9,   /* Bad credential format             */
    EMUNGE_BAD_VERSION          = 10,   /* Bad credential version            */
    EMUNGE_BAD_CIPHER           = 11,   /* Bad credential cipher type        */
    EMUNGE_BAD_ZIP              = 12,   /* Bad credential compression type   */
    EMUNGE_BAD_MAC              = 13,   /* Bad credential msg auth code type */
    EMUNGE_BAD_REALM            = 14,   /* Bad credential security realm     */
    EMUNGE_CRED_INVALID         = 15,   /* Credential invalid                */
    EMUNGE_CRED_EXPIRED         = 16,   /* Credential expired                */
    EMUNGE_CRED_REWOUND         = 17,   /* Credential created in the future  */
    EMUNGE_CRED_REPLAYED        = 18,   /* Credential replayed               */
    EMUNGE_CRED_UNAUTHORIZED    = 19,   /* Credential decode unauthorized    */
    EMUNGE_LAST_ENTRY
} munge_err_t;


/*****************************************************************************
 *  Primary Functions
 *****************************************************************************/

BEGIN_C_DECLS

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
 *    If a [ctx] was specified, it may contain a more detailed error
 *    message accessible via munge_ctx_strerror().
 */

munge_err_t munge_decode (const char *cred, munge_ctx_t ctx,
                          void **buf, int *len, uid_t *uid, gid_t *gid);
/*
 *  Validates the NUL-terminated munged credential [cred].
 *  If [ctx] is not NULL, it will be set to the munge context used to
 *    encode the credential.
 *  If [buf] and [len] are not NULL, [buf] will be set to the optional
 *    data munged into the credential and [len] will be set to its length.
 *    An additional NUL is appended to [buf] which is not included in [len].
 *    The caller is responsible for freeing the memory referenced by [buf].
 *    If no data was munged into the credential, [buf] will be set to NULL
 *    and [len] will be set to 0.  Note that in the case of some errors
 *    (ie, EMUNGE_CRED_EXPIRED, EMUNGE_CRED_REWOUND, EMUNGE_CRED_REPLAYED),
 *    [buf] and [len] will be updated as appropriate.
 *  If [uid] or [gid] is not NULL, they will be set to the UID/GID
 *    of the process that created the credential.
 *  Returns EMUNGE_SUCCESS if the credential is valid; o/w, returns the
 *    munge error number.  If a [ctx] was specified, it may contain a
 *    more detailed error message accessible via munge_ctx_strerror().
 */

const char * munge_strerror (munge_err_t e);
/*
 *  Returns a descriptive string describing the munge errno [e].
 */

END_C_DECLS


/*****************************************************************************
 *  Context Functions
 ***************************************************************************** 
 *  The context passed to munge_encode() is treated read-only except for the
 *    error message that is set when an error is returned.
 *  The context passed to munge_decode() is set according to the context used
 *    to encode the credential; however, on error, its settings may be in a
 *    state which is invalid for encoding.
 *  Consequently, separate contexts should be used for encoding and decoding.
 *  A context should not be shared between threads unless it is protected by
 *    a mutex; however, a better alternative is to use a separate context
 *    (or two) for each thread, either by creating a new one or copying an
 *    existing one.
 *****************************************************************************/

BEGIN_C_DECLS

munge_ctx_t munge_ctx_create (void);
/*
 *  Creates and returns a new munge context, or NULL on error (out-of-memory).
 *  Abandoning a context without calling munge_ctx_destroy() will result
 *    in a memory leak.
 */

munge_ctx_t munge_ctx_copy (munge_ctx_t ctx);
/*
 *  Copies the context [ctx], returning a new munge context or NULL on error.
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

END_C_DECLS


/*****************************************************************************
 *  Enumeration Functions
 *****************************************************************************/

BEGIN_C_DECLS

int munge_enum_is_valid (munge_enum_t type, int val);
/*
 *  Returns non-zero if the given value [val] is a valid enumeration of the
 *    specified [type] in the software configuration as currently compiled;
 *    o/w, returns 0.
 */

const char * munge_enum_int_to_str (munge_enum_t type, int val);
/*
 *  Converts the munge enumeration [val] of the specified [type] into a
 *    text string.
 *  Returns a NUL-terminated constant text string, or NULL on error;
 *    this string should not be freed or modified by the caller.
 */

int munge_enum_str_to_int (munge_enum_t type, const char *str);
/*
 *  Converts the NUL-terminated case-insensitive string [str] into
 *    the corresponding munge enumeration of the specified [type].
 *  Returns a munge enumeration on success (>=0), or -1 on error.
 */

END_C_DECLS


#endif /* !MUNGE_H */
