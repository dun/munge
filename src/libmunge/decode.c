/*****************************************************************************
 *  $Id: decode.c,v 1.17 2004/09/23 21:10:11 dun Exp $
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
#include "munge_msg.h"
#include "str.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static void _decode_init (munge_ctx_t ctx, void **buf, int *len,
    uid_t *uid, gid_t *gid);

static munge_err_t _decode_req_v1 (munge_msg_t m, munge_ctx_t ctx,
    const char *cred);

static munge_err_t _decode_rsp_v1 (munge_msg_t m, munge_ctx_t ctx,
    void **buf, int *len, uid_t *uid, gid_t *gid);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

munge_err_t
munge_decode (const char *cred, munge_ctx_t ctx,
              void **buf, int *len, uid_t *uid, gid_t *gid)
{
    munge_err_t e;
    munge_msg_t m;

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
    if ((e = munge_msg_create (&m, -1)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _decode_req_v1 (m, ctx, cred)) != EMUNGE_SUCCESS)
        ;
    else if ((e = munge_msg_client_xfer (&m, ctx)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _decode_rsp_v1 (m, ctx, buf, len, uid, gid)) !=EMUNGE_SUCCESS)
        ;
    /*  Clean up and return.
     */
    if (ctx) {
        _munge_ctx_set_err (ctx, e, m->errstr);
        m->errstr = NULL;
    }
    munge_msg_destroy (m);
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
        ctx->zip = -1;
        ctx->mac = -1;
        if (ctx->realm) {
            free (ctx->realm);
            ctx->realm = NULL;
        }
        ctx->ttl = -1;
        ctx->addr.s_addr = 0;
        ctx->time0 = -1;
        ctx->time1 = -1;
        ctx->auth_uid = -1;
        ctx->auth_gid = -1;
        ctx->errnum = EMUNGE_SUCCESS;
        if (ctx->errstr) {
            free (ctx->errstr);
            ctx->errstr = NULL;
        }
    }
    if (buf) {
        *buf = NULL;
    }
    if (len) {
        *len = 0;
    }
    if (uid) {
        *uid = -1;
    }
    if (gid) {
        *gid = -1;
    }
    return;
}


static munge_err_t
_decode_req_v1 (munge_msg_t m, munge_ctx_t ctx, const char *cred)
{
/*  Creates a Decode Request message to be sent to the local munge daemon.
 *  The inputs to this message are as follows:
 *    data_len, data.
 */
    struct munge_msg_v1 *m1;

    assert (m != NULL);
    assert (m->pbody == NULL);
    assert (cred != NULL);
    assert (strlen (cred) > 0);

    m->head.type = MUNGE_MSG_DEC_REQ;

    m->pbody_len = sizeof (struct munge_msg_v1);
    if (!(m->pbody = malloc (m->pbody_len))) {
        return (EMUNGE_NO_MEMORY);
    }
    /*  Init ints to 0, ptrs to NULL.
     */
    memset (m->pbody, 0, m->pbody_len);
    m1 = m->pbody;
    /*
     *  Pass the NUL-terminated credential to be decoded.
     */
    m1->data_len = strlen (cred) + 1;
    m1->data = (void *) cred;
    return (EMUNGE_SUCCESS);
}


static munge_err_t
_decode_rsp_v1 (munge_msg_t m, munge_ctx_t ctx,
               void **buf, int *len, uid_t *uid, gid_t *gid)
{
/*  Extracts a Decode Response message received from the local munge daemon.
 *  The outputs from this message are as follows:
 *    cipher, zip, mac, realm, ttl, addr, time0, time1,
 *    uid, gid, auth_uid, auth_gid, data_len, data, error_num, error_str.
 *  Note that the security realm string here is NUL-terminated.
 *  Note that error_num and error_str are set by _munge_ctx_set_err()
 *    called from munge_decode() (ie, the parent of this stack frame).
 */
    struct munge_msg_v1 *m1;
    unsigned char       *p;
    int                  n;

    assert (m != NULL);

    m1 = (struct munge_msg_v1 *) m->pbody;
    /*
     *  Perform sanity checks.
     */
    if (m->head.type != MUNGE_MSG_DEC_RSP) {
        munge_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Client received invalid message type %d", m->head.type));
        return (EMUNGE_SNAFU);
    }
    /*  Return the result.
     */
    if (ctx) {
        ctx->cipher = m1->cipher;
        ctx->zip = m1->zip;
        ctx->mac = m1->mac;
        ctx->realm = (m1->realm ? strdup (m1->realm) : NULL);
        ctx->ttl = m1->ttl;
        ctx->addr.s_addr = m1->addr.s_addr;;
        ctx->time0 = m1->time0;
        ctx->time1 = m1->time1;
        ctx->auth_uid = m1->auth_uid;
        ctx->auth_gid = m1->auth_gid;
    }
    if (buf && len && (m1->data_len > 0)) {
        n = m1->data_len + 1;
        if (!(p = malloc (n))) {
            munge_msg_set_err (m, EMUNGE_NO_MEMORY,
                strdupf ("Client unable to allocate %d bytes for data", n));
        }
        memcpy (p, m1->data, m1->data_len);
        p[m1->data_len] = '\0';
        *buf = p;
    }
    if (len) {
        *len = m1->data_len;
    }
    if (uid) {
        *uid = m1->cred_uid;
    }
    if (gid) {
        *gid = m1->cred_gid;
    }
    return (m1->error_num);
}
