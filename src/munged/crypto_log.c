/*****************************************************************************
 *  $Id: crypto_log.c,v 1.1 2003/04/08 18:16:16 dun Exp $
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
