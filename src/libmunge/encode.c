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

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <munge.h>
#include "ctx.h"
#include "m_msg.h"
#include "m_msg_client.h"
#include "str.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static void _encode_init (char **cred, munge_ctx_t ctx);

static munge_err_t _encode_req (m_msg_t m, munge_ctx_t ctx,
    const void *buf, int len);

static munge_err_t _encode_rsp (m_msg_t m, char **cred);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
munge_encode (char **cred, munge_ctx_t ctx, const void *buf, int len)
{
    munge_err_t  e;
    m_msg_t      m;

    /*  Init output parms in case of early return.
     */
    _encode_init (cred, ctx);
    /*
     *  Ensure a ptr exists for returning the credential to the caller.
     */
    if (!cred) {
        return (_munge_ctx_set_err (ctx, EMUNGE_BAD_ARG,
            strdup ("No address specified for returning the credential")));
    }
    /*  Ask the daemon to encode a credential.
     */
    if ((e = m_msg_create (&m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _encode_req (m, ctx, buf, len)) != EMUNGE_SUCCESS)
        ;
    else if ((e = m_msg_client_xfer (&m, MUNGE_MSG_ENC_REQ, ctx))
            != EMUNGE_SUCCESS)
        ;
    else if ((e = _encode_rsp (m, cred)) != EMUNGE_SUCCESS)
        ;
    /*  Clean up and return.
     */
    if (ctx) {
        _munge_ctx_set_err (ctx, e, m->error_str);
        m->error_is_copy = 1;
    }
    m_msg_destroy (m);
    return (e);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void
_encode_init (char **cred, munge_ctx_t ctx)
{
/*  Initialize output parms in case of early return.
 */
    if (cred) {
        *cred = NULL;
    }
    if (ctx) {
        ctx->error_num = EMUNGE_SUCCESS;
        if (ctx->error_str) {
            free (ctx->error_str);
            ctx->error_str = NULL;
        }
    }
    return;
}


static munge_err_t
_encode_req (m_msg_t m, munge_ctx_t ctx, const void *buf, int len)
{
/*  Creates an Encode Request message to be sent to the local munge daemon.
 *  The inputs to this message are as follows:
 *    cipher, mac, zip, realm_len, realm_str, ttl, auth_uid, auth_gid,
 *    data_len, data.
 */
    assert (m != NULL);

    /*  Set opts from ctx (if present); o/w, use defaults.
     */
    if (ctx) {
        m->cipher = ctx->cipher;
        m->mac = ctx->mac;
        m->zip = ctx->zip;
        if (ctx->realm_str) {
            m->realm_len = strlen (ctx->realm_str) + 1;
            m->realm_str = ctx->realm_str;
            m->realm_is_copy = 1;
        }
        else {
            m->realm_len = 0;
            m->realm_str = NULL;
        }
        m->ttl = ctx->ttl;
        m->auth_uid = ctx->auth_uid;
        m->auth_gid = ctx->auth_gid;
    }
    else {
        m->cipher = MUNGE_CIPHER_DEFAULT;
        m->zip = MUNGE_ZIP_DEFAULT;
        m->mac = MUNGE_MAC_DEFAULT;
        m->realm_len = 0;
        m->realm_str = NULL;
        m->ttl = MUNGE_TTL_DEFAULT;
        m->auth_uid = MUNGE_UID_ANY;
        m->auth_gid = MUNGE_GID_ANY;
    }
    /*  Pass optional data to be encoded into the credential.
     */
    m->data_len = len;
    m->data = (void *) buf;
    m->data_is_copy = 1;
    return (EMUNGE_SUCCESS);
}


static munge_err_t
_encode_rsp (m_msg_t m, char **cred)
{
/*  Extracts an Encode Response message received from the local munge daemon.
 *  The outputs from this message are as follows:
 *    error_num, error_len, error_str, data_len, data.
 *  Note that error_num and error_str are set by _munge_ctx_set_err()
 *    called from munge_encode() (ie, the parent of this stack frame).
 *  Note that the [cred] is NUL-terminated.
 */
    assert (m != NULL);
    assert (cred != NULL);

    /*  Perform sanity checks.
     */
    if (m->type != MUNGE_MSG_ENC_RSP) {
        m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Client received invalid message type %d", m->type));
        return (EMUNGE_SNAFU);
    }
    if (m->data_len <= 0) {
        m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Client received invalid data length %d", m->data_len));
        return (EMUNGE_SNAFU);
    }
    /*  Return the credential to the caller.
     */
    assert (* ((unsigned char *) m->data + m->data_len) == '\0');
    *cred = m->data;
    m->data_is_copy = 1;
    return (m->error_num);
}
