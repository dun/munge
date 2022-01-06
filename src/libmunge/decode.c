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
#include "common.h"
#include "ctx.h"
#include "m_msg.h"
#include "m_msg_client.h"
#include "str.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static void _decode_init (munge_ctx_t ctx, void **buf, int *len,
    uid_t *uid, gid_t *gid);

static munge_err_t _decode_req (m_msg_t m, munge_ctx_t ctx,
    const char *cred);

static munge_err_t _decode_rsp (m_msg_t m, munge_ctx_t ctx,
    void **buf, int *len, uid_t *uid, gid_t *gid);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
munge_decode (const char *cred, munge_ctx_t ctx,
              void **buf, int *len, uid_t *uid, gid_t *gid)
{
    munge_err_t  e;
    m_msg_t      m;

    /*  Init output parms in case of early return.
     */
    _decode_init (ctx, buf, len, uid, gid);
    /*
     *  Ensure a credential exists for decoding.
     */
    if ((cred == NULL) || (*cred == '\0')) {
        return (_munge_ctx_set_err (ctx, EMUNGE_BAD_ARG,
            strdup ("No credential specified")));
    }
    /*  Ask the daemon to decode a credential.
     */
    if ((e = m_msg_create (&m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _decode_req (m, ctx, cred)) != EMUNGE_SUCCESS)
        ;
    else if ((e = m_msg_client_xfer (&m, MUNGE_MSG_DEC_REQ, ctx))
            != EMUNGE_SUCCESS)
        ;
    else if ((e = _decode_rsp (m, ctx, buf, len, uid, gid)) != EMUNGE_SUCCESS)
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
_decode_init (munge_ctx_t ctx, void **buf, int *len, uid_t *uid, gid_t *gid)
{
/*  Initialize output parms in case of early return.
 */
    if (ctx) {
        ctx->cipher = -1;
        ctx->mac = -1;
        ctx->zip = -1;
        if (ctx->realm_str) {
            free (ctx->realm_str);
            ctx->realm_str = NULL;
        }
        ctx->ttl = -1;
        ctx->addr.s_addr = 0;
        ctx->time0 = -1;
        ctx->time1 = -1;
        ctx->auth_uid = UID_SENTINEL;
        ctx->auth_gid = GID_SENTINEL;
        ctx->error_num = EMUNGE_SUCCESS;
        if (ctx->error_str) {
            free (ctx->error_str);
            ctx->error_str = NULL;
        }
    }
    if (buf) {
        *buf = NULL;
    }
    if (len) {
        *len = 0;
    }
    if (uid) {
        *uid = UID_SENTINEL;
    }
    if (gid) {
        *gid = GID_SENTINEL;
    }
    return;
}


static munge_err_t
_decode_req (m_msg_t m, munge_ctx_t ctx, const char *cred)
{
/*  Creates a Decode Request message to be sent to the local munge daemon.
 *  The inputs to this message are as follows:
 *    data_len, data.
 */
    assert (m != NULL);
    assert (cred != NULL);
    assert (strlen (cred) > 0);

    /*  Pass the NUL-terminated credential to be decoded.
     */
    m->data_len = strlen (cred) + 1;
    m->data = (void *) cred;
    m->data_is_copy = 1;
    return (EMUNGE_SUCCESS);
}


static munge_err_t
_decode_rsp (m_msg_t m, munge_ctx_t ctx,
               void **buf, int *len, uid_t *uid, gid_t *gid)
{
/*  Extracts a Decode Response message received from the local munge daemon.
 *  The outputs from this message are as follows:
 *    cipher, mac, zip, realm, ttl, addr, time0, time1, cred_uid, cred_gid,
 *    auth_uid, auth_gid, data_len, data, error_num, error_len, error_str.
 *  Note that error_num and error_str are set by _munge_ctx_set_err()
 *    called from munge_decode() (ie, the parent of this stack frame).
 */
    assert (m != NULL);

    /*  Perform sanity checks.
     */
    if (m->type != MUNGE_MSG_DEC_RSP) {
        m_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Client received invalid message type %d", m->type));
        return (EMUNGE_SNAFU);
    }
    /*  Return the result.
     */
    if (ctx) {
        ctx->cipher = m->cipher;
        ctx->mac = m->mac;
        ctx->zip = m->zip;
        if ((ctx->realm_str = m->realm_str) != NULL) {
            m->realm_is_copy = 1;
        }
        ctx->ttl = m->ttl;
        ctx->addr.s_addr = m->addr.s_addr;;
        ctx->time0 = m->time0;
        ctx->time1 = m->time1;
        ctx->auth_uid = m->auth_uid;
        ctx->auth_gid = m->auth_gid;
    }
    if (buf && len && (m->data_len > 0)) {
        assert (* ((unsigned char *) m->data + m->data_len) == '\0');
        *buf = m->data;
        m->data_is_copy = 1;
    }
    if (len) {
        *len = m->data_len;
    }
    if (uid) {
        *uid = m->cred_uid;
    }
    if (gid) {
        *gid = m->cred_gid;
    }
    return (m->error_num);
}
