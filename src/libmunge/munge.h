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


#ifndef MUNGE_H
#define MUNGE_H

#include <sys/types.h>


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

/*  MUNGE context opaque data type
 */
typedef struct munge_ctx * munge_ctx_t;

/*  MUNGE context options
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
    MUNGE_OPT_GID_RESTRICTION   = 10    /* GID able to decode cred (gid_t)   */
} munge_opt_t;

/*  MUNGE symmetric cipher types
 */
typedef enum munge_cipher {
    MUNGE_CIPHER_NONE           =  0,   /* encryption disabled               */
    MUNGE_CIPHER_DEFAULT        =  1,   /* default ciphr specified by daemon */
    MUNGE_CIPHER_BLOWFISH       =  2,   /* Blowfish CBC w/ 64b-blk/128b-key  */
    MUNGE_CIPHER_CAST5          =  3,   /* CAST5 CBC w/ 64b-blk/128b-key     */
    MUNGE_CIPHER_AES128         =  4,   /* AES CBC w/ 128b-blk/128b-key      */
    MUNGE_CIPHER_AES256         =  5,   /* AES CBC w/ 128b-blk/256b-key      */
    MUNGE_CIPHER_LAST_ITEM
} munge_cipher_t;

/*  MUNGE message authentication code types
 */
typedef enum munge_mac {
    MUNGE_MAC_NONE              =  0,   /* mac disabled -- invalid, btw      */
    MUNGE_MAC_DEFAULT           =  1,   /* default mac specified by daemon   */
    MUNGE_MAC_MD5               =  2,   /* MD5 w/ 128b-digest                */
    MUNGE_MAC_SHA1              =  3,   /* SHA-1 w/ 160b-digest              */
    MUNGE_MAC_RIPEMD160         =  4,   /* RIPEMD-160 w/ 160b-digest         */
    MUNGE_MAC_SHA256            =  5,   /* SHA-256 w/ 256b-digest            */
    MUNGE_MAC_SHA512            =  6,   /* SHA-512 w/ 512b-digest            */
    MUNGE_MAC_LAST_ITEM
} munge_mac_t;

/*  MUNGE compression types
 */
typedef enum munge_zip {
    MUNGE_ZIP_NONE              =  0,   /* compression disabled              */
    MUNGE_ZIP_DEFAULT           =  1,   /* default zip specified by daemon   */
    MUNGE_ZIP_BZLIB             =  2,   /* bzip2 by Julian Seward            */
    MUNGE_ZIP_ZLIB              =  3,   /* zlib "deflate" by Gailly & Adler  */
    MUNGE_ZIP_LAST_ITEM
} munge_zip_t;

/*  MUNGE credential time-to-live (in seconds)
 */
typedef enum munge_ttl {
    MUNGE_TTL_MAXIMUM           = -1,   /* maximum ttl allowed by daemon     */
    MUNGE_TTL_DEFAULT           =  0    /* default ttl specified by daemon   */
} munge_ttl_t;

/*  MUNGE UID restrictions for credential decoding
 */
typedef enum munge_uid {
    MUNGE_UID_ANY               = -1    /* do not restrict decode via uid    */
} munge_uid_t;

/*  MUNGE GID restrictions for credential decoding
 */
typedef enum munge_gid {
    MUNGE_GID_ANY               = -1    /* do not restrict decode via gid    */
} munge_gid_t;

/*  MUNGE enum types for str/int conversions
 */
typedef enum munge_enum {
    MUNGE_ENUM_CIPHER           =  0,   /* cipher enum type                  */
    MUNGE_ENUM_MAC              =  1,   /* mac enum type                     */
    MUNGE_ENUM_ZIP              =  2    /* zip enum type                     */
} munge_enum_t;

/*  MUNGE error codes
 *
 *  Error codes are in the range [1..255] in order to provide
 *    a meaningful return status when returned via exit().
 */
typedef enum munge_err {
    EMUNGE_SUCCESS              =  0,   /* Success: Whoohoo!                 */
    EMUNGE_SNAFU                =  1,   /* Internal error: Doh!              */
    EMUNGE_BAD_ARG              =  2,   /* Invalid argument                  */
    EMUNGE_BAD_LENGTH           =  3,   /* Exceeded maximum message length   */
    EMUNGE_OVERFLOW             =  4,   /* Buffer overflow                   */
    EMUNGE_NO_MEMORY            =  5,   /* Out of memory                     */
    EMUNGE_SOCKET               =  6,   /* Socket communication error        */
    EMUNGE_TIMEOUT              =  7,   /* Socket timeout (NOT USED)         */
    EMUNGE_BAD_CRED             =  8,   /* Invalid credential format         */
    EMUNGE_BAD_VERSION          =  9,   /* Invalid credential version        */
    EMUNGE_BAD_CIPHER           = 10,   /* Invalid cipher type               */
    EMUNGE_BAD_MAC              = 11,   /* Invalid MAC type                  */
    EMUNGE_BAD_ZIP              = 12,   /* Invalid compression type          */
    EMUNGE_BAD_REALM            = 13,   /* Unrecognized security realm       */
    EMUNGE_CRED_INVALID         = 14,   /* Invalid credential                */
    EMUNGE_CRED_EXPIRED         = 15,   /* Expired credential                */
    EMUNGE_CRED_REWOUND         = 16,   /* Rewound credential, future ctime  */
    EMUNGE_CRED_REPLAYED        = 17,   /* Replayed credential               */
    EMUNGE_CRED_UNAUTHORIZED    = 18    /* Unauthorized credential decode    */
} munge_err_t;

/*  MUNGE defines for backwards-compatibility
 */
#define MUNGE_CIPHER_AES_128 MUNGE_CIPHER_AES128


/*****************************************************************************
 *  Primary Functions
 *****************************************************************************/

BEGIN_C_DECLS

munge_err_t munge_encode (char **cred, munge_ctx_t ctx,
                          const void *buf, int len);
/*
 *  Creates a credential contained in a NUL-terminated base64 string.
 *    A payload specified by a buffer [buf] of length [len] can be
 *    encapsulated in as well.
 *  If the munge context [ctx] is NULL, the default context will be used.
 *  A pointer to the resulting credential is returned via [cred]; the caller
 *    is responsible for freeing this memory.
 *  Returns EMUNGE_SUCCESS if the credential is successfully created;
 *    o/w, sets [cred] to NULL and returns the munge error number.
 *    If a [ctx] was specified, it may contain a more detailed error
 *    message accessible via munge_ctx_strerror().
 */

munge_err_t munge_decode (const char *cred, munge_ctx_t ctx,
                          void **buf, int *len, uid_t *uid, gid_t *gid);
/*
 *  Validates the NUL-terminated credential [cred].
 *  If the munge context [ctx] is not NULL, it will be set to that used
 *    to encode the credential.
 *  If [buf] and [len] are not NULL, memory will be allocated for the
 *    encapsulated payload, [buf] will be set to point to this data, and [len]
 *    will be set to its length.  An additional NUL character will be appended
 *    to this payload data but not included in its length.  If no payload
 *    exists, [buf] will be set to NULL and [len] will be set to 0.
 *    For certain errors (ie, EMUNGE_CRED_EXPIRED, EMUNGE_CRED_REWOUND,
 *    EMUNGE_CRED_REPLAYED), payload memory will still be allocated if
 *    necessary.  The caller is responsible for freeing this memory.
 *  If [uid] or [gid] is not NULL, they will be set to the UID/GID of the
 *    process that created the credential.
 *  Returns EMUNGE_SUCCESS if the credential is valid; o/w, returns the
 *    munge error number.  If a [ctx] was specified, it may contain a
 *    more detailed error message accessible via munge_ctx_strerror().
 */

const char * munge_strerror (munge_err_t e);
/*
 *  Returns a descriptive string describing the munge errno [e].
 *    This string should not be freed or modified by the caller.
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
 *  Creates and returns a new munge context or NULL on error.
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
 *  Returns a descriptive text string describing the munge error number
 *    according to the context [ctx], or NULL if no error condition exists.
 *  This message may be more detailed than that returned by munge_strerror().
 *  This string should not be freed or modified by the caller.
 */

munge_err_t munge_ctx_get (munge_ctx_t ctx, int opt, ...);
/*
 *  Gets the value for the option [opt] (of munge_opt_t) associated with the
 *    munge context [ctx], storing the result in the subsequent pointer
 *    argument.  Refer to the munge_opt_t enum comments for argument types.
 *    If the result is a string, that string should not be freed or modified
 *    by the caller.
 *  Returns EMUNGE_SUCCESS on success; o/w, returns the munge error number.
 */

munge_err_t munge_ctx_set (munge_ctx_t ctx, int opt, ...);
/*
 *  Sets the value for the option [opt] (of munge_opt_t) associated with the
 *    munge context [ctx], using the value of the subsequent argument.
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
 *  Returns non-zero if the given value [val] is a valid enumeration of
 *    the specified type [type] in the software configuration as currently
 *    compiled; o/w, returns 0.
 *  Some enumerations corresond to options that can only be enabled at
 *    compile-time.
 */

const char * munge_enum_int_to_str (munge_enum_t type, int val);
/*
 *  Converts the munge enumeration [val] of the specified type [type]
 *    into a text string.
 *  Returns a NUL-terminated constant text string, or NULL on error;
 *    this string should not be freed or modified by the caller.
 */

int munge_enum_str_to_int (munge_enum_t type, const char *str);
/*
 *  Converts the NUL-terminated case-insensitive string [str] into the
 *    corresponding munge enumeration of the specified type [type].
 *  Returns a munge enumeration on success (>=0), or -1 on error.
 */

END_C_DECLS


#endif /* !MUNGE_H */
