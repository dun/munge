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


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <munge.h>
#include "common.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#if HAVE_LIBGCRYPT || HAVE_EVP_AES_128_CBC
#  define MUNGE_CIPHER_AES128_FLAG      1
#else
#  define MUNGE_CIPHER_AES128_FLAG      0
#endif

#if HAVE_LIBGCRYPT || (HAVE_EVP_AES_256_CBC && HAVE_EVP_SHA256)
#  define MUNGE_CIPHER_AES256_FLAG      1
#else
#  define MUNGE_CIPHER_AES256_FLAG      0
#endif

#if HAVE_LIBGCRYPT || HAVE_EVP_SHA256
#  define MUNGE_MAC_SHA256_FLAG         1
#else
#  define MUNGE_MAC_SHA256_FLAG         0
#endif

#if HAVE_LIBGCRYPT || HAVE_EVP_SHA512
#  define MUNGE_MAC_SHA512_FLAG         1
#else
#  define MUNGE_MAC_SHA512_FLAG         0
#endif

#if HAVE_PKG_BZLIB
#  define MUNGE_ZIP_BZLIB_FLAG          1
#else
#  define MUNGE_ZIP_BZLIB_FLAG          0
#endif

#if HAVE_PKG_ZLIB
#  define MUNGE_ZIP_ZLIB_FLAG           1
#else
#  define MUNGE_ZIP_ZLIB_FLAG           0
#endif


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct munge_enum_table {
    int         value;                  /* munge enumeration or -1           */
    const char *string;                 /* descriptive string or NULL        */
    int         is_valid;               /* true (1), false (0), error (-1)   */
};

typedef struct munge_enum_table * munge_enum_table_t;


/*****************************************************************************
 *  Variables
 *****************************************************************************/

static struct munge_enum_table _munge_cipher_table[] = {
    { MUNGE_CIPHER_NONE,        "none",         1                        },
    { MUNGE_CIPHER_DEFAULT,     "default",      1                        },
    { MUNGE_CIPHER_BLOWFISH,    "blowfish",     1                        },
    { MUNGE_CIPHER_CAST5,       "cast5",        1                        },
    { MUNGE_CIPHER_AES128,      "aes128",       MUNGE_CIPHER_AES128_FLAG },
    { MUNGE_CIPHER_AES256,      "aes256",       MUNGE_CIPHER_AES256_FLAG },
    { -1,                        NULL,         -1                        }
};

static struct munge_enum_table _munge_mac_table[] = {
    { MUNGE_MAC_NONE,           "none",         0                        },
    { MUNGE_MAC_DEFAULT,        "default",      1                        },
    { MUNGE_MAC_MD5,            "md5",          1                        },
    { MUNGE_MAC_SHA1,           "sha1",         1                        },
    { MUNGE_MAC_RIPEMD160,      "ripemd160",    1                        },
    { MUNGE_MAC_SHA256,         "sha256",       MUNGE_MAC_SHA256_FLAG    },
    { MUNGE_MAC_SHA512,         "sha512",       MUNGE_MAC_SHA512_FLAG    },
    { -1,                        NULL,         -1                        }
};

static struct munge_enum_table _munge_zip_table[] = {
    { MUNGE_ZIP_NONE,           "none",         1                        },
    { MUNGE_ZIP_DEFAULT,        "default",      1                        },
    { MUNGE_ZIP_BZLIB,          "bzlib",        MUNGE_ZIP_BZLIB_FLAG     },
    { MUNGE_ZIP_ZLIB,           "zlib",         MUNGE_ZIP_ZLIB_FLAG      },
    { -1,                        NULL,         -1                        }
};


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static munge_enum_table_t _munge_enum_lookup (munge_enum_t type);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

int
munge_enum_is_valid (munge_enum_t type, int val)
{
    munge_enum_table_t  tp;
    int                 i;

    if (!(tp = _munge_enum_lookup (type))) {
        return (0);
    }
    for (i = 0; tp[i].string != NULL; i++) {
        if (val == tp[i].value) {
            return (tp[i].is_valid);
        }
    }
    return (0);
}


const char *
munge_enum_int_to_str (munge_enum_t type, int val)
{
    munge_enum_table_t  tp;
    int                 i;

    if (!(tp = _munge_enum_lookup (type))) {
        return (NULL);
    }
    for (i = 0; tp[i].string != NULL; i++) {
        if (val == tp[i].value) {
            return (tp[i].string);
        }
    }
    return (NULL);
}


int
munge_enum_str_to_int (munge_enum_t type, const char *str)
{
    munge_enum_table_t  tp;
    int                 i;
    int                 n;
    char               *p;
    int                 errno_bak, errno_sav;

    if (!str || !*str) {
        return (-1);
    }
    if (!(tp = _munge_enum_lookup (type))) {
        return (-1);
    }
    /*  Check if the given string matches a valid string.
     *  Also determine the number of strings in the array.
     */
    for (i = 0; tp[i].string != NULL; i++) {
        if (!strcasecmp (str, tp[i].string)) {
            return (tp[i].value);
        }
    }
    /*  Check if the given string matches a valid enum.
     *  Save & restore errno in order to check for strtol() errors.
     *    This check is technically unnecessary since (str == p) should check
     *    for no digits and (*p != '\0') should check for trailing non-digits.
     *    ERANGE is not compared against LONG_MIN or LONG_MAX since these enums
     *    can never get that large.  It's just an extra check for the paranoid.
     */
    errno_bak = errno;
    errno = 0;
    n = strtol (str, &p, 10);
    errno_sav = errno;
    errno = errno_bak;

    if ((errno_sav != 0) || (str == p) || (*p != '\0')) {
        return (-1);
    }
    if ((n < 0) || (n >= i)) {
        return (-1);
    }
    return (n);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static munge_enum_table_t
_munge_enum_lookup (munge_enum_t type)
{
    switch (type) {
        case MUNGE_ENUM_CIPHER:
            return (_munge_cipher_table);
        case MUNGE_ENUM_MAC:
            return (_munge_mac_table);
        case MUNGE_ENUM_ZIP:
            return (_munge_zip_table);
        default:
            return (NULL);
    }
    return (NULL);
}
