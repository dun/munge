/*****************************************************************************
 *  $Id: encode.c,v 1.13 2004/05/06 01:41:12 dun Exp $
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
#include "auth_send.h"
#include "ctx.h"
#include "msg_client.h"
#include "munge_defs.h"
#include "munge_msg.h"
#include "str.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static void encode_init (char **cred, munge_ctx_t ctx);

static munge_err_t encode_req_v1 (munge_msg_t m, munge_ctx_t ctx,
    const void *buf, int len);

static munge_err_t encode_rsp_v1 (munge_msg_t m, char **cred);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_err_t
munge_encode (char **cred, munge_ctx_t ctx, const void *buf, int len)
{
    char *socket;
    munge_err_t e;
    munge_msg_t m;

    /*  Init output parms in case of early return.
     */
    encode_init (cred, ctx);
    /*
     *  Ensure a ptr exists for returning the credential to the caller.
     */
    if (!cred) {
        return (_munge_ctx_set_err (ctx, EMUNGE_BAD_ARG,
            strdup ("No address specified for returning the credential")));
    }
    /*
     *  Determine name of unix domain socket for communication with munged.
     */
    if (!ctx || !(socket = ctx->socket)) {
        socket = MUNGE_SOCKET_NAME;
    }
    /*  Ask the daemon to encode a credential.
     */
    if ((e = _munge_msg_create (&m, -1)) != EMUNGE_SUCCESS)
        ;
    else if ((e = encode_req_v1 (m, ctx, buf, len)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _munge_msg_client_connect (m, socket)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _munge_msg_send (m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = auth_send (m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _munge_msg_reset (m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _munge_msg_recv (m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = _munge_msg_client_disconnect (m)) != EMUNGE_SUCCESS)
        ;
    else if ((e = encode_rsp_v1 (m, cred)) != EMUNGE_SUCCESS)
        ;
    /*  Clean up and return.
     */
    if (ctx) {
        _munge_ctx_set_err (ctx, e, m->errstr);
        m->errstr = NULL;
    }
    _munge_msg_destroy (m);
    return (e);
}


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static void
encode_init (char **cred, munge_ctx_t ctx)
{
/*  Initialize output parms in case of early return.
 */
    if (cred) {
        *cred = NULL;
    }
    if (ctx) {
        ctx->errnum = EMUNGE_SUCCESS;
        if (ctx->errstr) {
            free (ctx->errstr);
            ctx->errstr = NULL;
        }
    }
    return;
}


static munge_err_t
encode_req_v1 (munge_msg_t m, munge_ctx_t ctx, const void *buf, int len)
{
/*  Creates an Encode Request message to be sent to the local munge daemon.
 *  The inputs to this message are as follows:
 *    cipher, zip, mac, realm_len, realm, ttl, auth_uid, auth_gid,
 *    data_len, data.
 *  Note that the security realm string here is NUL-terminated.
 */
    struct munge_msg_v1 *m1;

    assert (m != NULL);
    assert (m->pbody == NULL);

    m->head.type = MUNGE_MSG_ENC_REQ;

    m->pbody_len = sizeof (struct munge_msg_v1);
    if (!(m->pbody = malloc (m->pbody_len))) {
        return (EMUNGE_NO_MEMORY);
    }
    /*  Init ints to 0, ptrs to NULL.
     */
    memset (m->pbody, 0, m->pbody_len);
    m1 = m->pbody;
    /*
     *  Set opts from ctx (if present); o/w, use defaults.
     */
    if (ctx) {
        m1->cipher = ctx->cipher;
        m1->zip = ctx->zip;
        m1->mac = ctx->mac;
        if (ctx->realm) {
            m1->realm_len = strlen (ctx->realm) + 1;
            m1->realm = ctx->realm;
        }
        else {
            m1->realm_len = 0;
            m1->realm = NULL;
        }
        m1->ttl = ctx->ttl;
        m1->auth_uid = ctx->auth_uid;
        m1->auth_gid = ctx->auth_gid;
    }
    else {
        m1->cipher = MUNGE_CIPHER_DEFAULT;
        m1->zip = MUNGE_ZIP_DEFAULT;
        m1->mac = MUNGE_MAC_DEFAULT;
        m1->realm_len = 0;
        m1->realm = NULL;
        m1->ttl = MUNGE_TTL_DEFAULT;
        m1->auth_uid = MUNGE_UID_ANY;
        m1->auth_gid = MUNGE_GID_ANY;
    }
    /*  Pass optional data to be encoded into the credential.
     */
    m1->data_len = len;
    m1->data = (void *) buf;
    return (EMUNGE_SUCCESS);
}


static munge_err_t
encode_rsp_v1 (munge_msg_t m, char **cred)
{
/*  Extracts an Encode Response message received from the local munge daemon.
 *  The relevant outputs from this message are as follows:
 *    data_len, data, error_num, error_str.
 *  Note that error_num and error_str are set by _munge_ctx_set_err()
 *    called from munge_encode() (ie, the parent of this stack frame).
 *  The ignored outputs from this message are as follows:
 *    cipher, zip, mac, realm_len, realm, time0, ttl, uid, gid,
 *    auth_uid, auth_gid.
 *  These are ignored because the encode() ctx is considered read-only
 *    (with the exception of using it to pass detailed error messages).
 *    This allows the same ctx to be used to encode multiple credentials
 *    with the same options.
 *  Note that the [cred] is NUL-terminated.
 */
    struct munge_msg_v1 *m1;
    unsigned char       *p;
    int                  n;

    assert (m != NULL);
    assert (cred != NULL);

    m1 = (struct munge_msg_v1 *) m->pbody;
    /*
     *  Perform sanity checks.
     */
    if (m->head.type != MUNGE_MSG_ENC_RSP) {
        _munge_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Client received invalid message type %d", m->head.type));
        return (EMUNGE_SNAFU);
    }
    if (m1->data_len <= 0) {
        _munge_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Client received invalid data length %d", m1->data_len));
        return (EMUNGE_SNAFU);
    }
    /*  Allocate memory for the credential string
     *    (including space for the terminating NUL).
     *  We can't simply return the 'data' field here as it
     *    lies in the middle of the message's memory allocation.
     */
    n = m1->data_len + 1;
    if (!(p = malloc (n))) {
        _munge_msg_set_err (m, EMUNGE_NO_MEMORY,
            strdupf ("Client unable to allocate %d bytes for data", n));
        return (EMUNGE_NO_MEMORY);
    }
    /*  Copy the credential.
     */
    assert (m1->data != NULL);
    memcpy (p, m1->data, m1->data_len);
    /*
     *  NUL-terminate the credential string.
     */
    p[m1->data_len] = '\0';
    /*
     *  Return the credential to the caller.
     */
    *cred = (char *) p;
    return (m1->error_num);
}
