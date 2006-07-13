/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2003-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory.
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
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

#include <assert.h>
#include <openssl/err.h>
#include "crypto_log.h"
#include "log.h"
#include "str.h"


#define CRYPTO_LOG_MAX_ERR_LEN     1024


void
crypto_log_msg (int priority)
{
    int         e;
    const char *data;
    int         flags;
    char        buf[CRYPTO_LOG_MAX_ERR_LEN];

    ERR_load_crypto_strings ();
    while ((e = ERR_get_error_line_data (NULL, NULL, &data, &flags)) != 0) {
#if HAVE_ERR_ERROR_STRING_N
        ERR_error_string_n (e, buf, sizeof (buf));
#else  /* !HAVE_ERR_ERROR_STRING_N */
        assert (sizeof (buf) >= 256);
        ERR_error_string (e, buf);
#endif /* !HAVE_ERR_ERROR_STRING_N */
        if (data && (flags & ERR_TXT_STRING)) {
            strcatf (buf, sizeof (buf), ":%s", data);
        }
        log_msg (priority, "%s", buf);
    }
    ERR_free_strings ();
    return;
}
