/*****************************************************************************
 *  $Id: code.c,v 1.1 2003/04/08 18:16:16 dun Exp $
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


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <munge.h>
#include "ctx.h"
#include "msg_client.h"
#include "munge_defs.h"


munge_err_t
munge_encode (char **cred, munge_ctx_t ctx, const void *buf, int len)
{
    char *socket;
    munge_err_t e;
    munge_msg_t m;

    if (!cred) {
        e = EMUNGE_BAD_ARG;
        goto end;
    }
    if (!ctx || !(socket = ctx->socket)) {
        socket = MUNGE_SOCKET_NAME;
    }
    e = _munge_msg_create (&m, -1, MUNGE_MSG_ENC_REQ);
    if (e != EMUNGE_SUCCESS)
        goto end;
    e = _munge_msg_client_enc_req_v1 (m, ctx, buf, len);
    if (e != EMUNGE_SUCCESS)
        goto end;
    e = _munge_msg_client_connect (m, socket);
    if (e != EMUNGE_SUCCESS)
        goto end;
    e = _munge_msg_send (m);
    if (e != EMUNGE_SUCCESS)
        goto end;
    e = _munge_msg_recv (m);
    if (e != EMUNGE_SUCCESS)
        goto end;
    e = _munge_msg_client_disconnect (m);
    if (e != EMUNGE_SUCCESS)
        goto end;
    e = _munge_msg_client_enc_rsp_v1 (m, cred);
    if (e != EMUNGE_SUCCESS)
        goto end;

end:
    if (ctx) {
        ctx->status = e;
        if (ctx->error) {
            free (ctx->error);
        }
        if (e == EMUNGE_SUCCESS) {
            ctx->error = NULL;
        }
        else {
            ctx->error = m->error;
            m->error = NULL;
        }
    }
    _munge_msg_destroy (m);
    return (e);
}


munge_err_t
munge_decode (const char *cred, munge_ctx_t ctx,
              void **buf, int *len, uid_t *uid, gid_t *gid)
{
    if ((cred == NULL) || (*cred == '\0')) {
        return (EMUNGE_BAD_ARG);
    }
    return (EMUNGE_SNAFU);
}


const char *
munge_strerror (munge_err_t errnum)
{
    switch (errnum) {
        case EMUNGE_SUCCESS:
            return ("Success");
        case EMUNGE_SNAFU:
            return ("Internal error");
        case EMUNGE_BAD_ARG:
            return ("Invalid argument");
        case EMUNGE_OVERFLOW:
            return ("Buffer overflow");
        case EMUNGE_NO_MEMORY:
            return ("Out of memory");
        case EMUNGE_NO_DAEMON:
            return ("Munged not responding");
        case EMUNGE_SOCKET:
            return ("Munged communication error");
        case EMUNGE_TIMEOUT:
            return ("Munged timed-out");
        case EMUNGE_BAD_CRED:
            return ("Invalid credential");
        case EMUNGE_BAD_VERSION:
            return ("Unrecognized credential version");
        case EMUNGE_BAD_CIPHER:
            return ("Unrecognized credential cipher type");
        case EMUNGE_BAD_ZIP:
            return ("Unrecognized credential zip type");
        case EMUNGE_BAD_MAC:
            return ("Unrecognized credential mac type");
        case EMUNGE_BAD_REALM:
            return ("Unrecognized credential security realm");
        case EMUNGE_CRED_EXPIRED:
            return ("Expired credential");
        case EMUNGE_CRED_REWOUND:
            return ("Rewound credential");
        case EMUNGE_CRED_REPLAYED:
            return ("Replayed credential");
        default:
            return ("Unknown error");
    }
    /* not reached */
}
