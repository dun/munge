/*****************************************************************************
 *  $Id: ctx.c,v 1.11 2004/04/03 01:12:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-155910.
 *
 *  Copyright (C) 2002-2004 The Regents of the University of California.
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
#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <munge.h>
#include "ctx.h"
#include "munge_defs.h"
#include "munge_msg.h"


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_ctx_t
munge_ctx_create (void)
{
    munge_ctx_t ctx;

    if (!(ctx = malloc (sizeof (struct munge_ctx)))) {
        return (NULL);
    }
    ctx->cipher = MUNGE_CIPHER_DEFAULT;
    ctx->zip = MUNGE_ZIP_DEFAULT;
    ctx->mac = MUNGE_MAC_DEFAULT;
    ctx->realm = NULL;
    ctx->ttl = MUNGE_TTL_DEFAULT;
    ctx->addr.s_addr = 0;
    ctx->time0 = 0;
    ctx->time1 = 0;
    ctx->socket = strdup (MUNGE_SOCKET_NAME);
    ctx->errnum = EMUNGE_SUCCESS;
    ctx->errstr = NULL;

    if (!(ctx->socket)) {
        munge_ctx_destroy (ctx);
        return (NULL);
    }
    return (ctx);
}


void
munge_ctx_destroy (munge_ctx_t ctx)
{
    assert (ctx != NULL);

    if (!ctx) {
        return;
    }
    if (ctx->realm) {
        free (ctx->realm);
    }
    if (ctx->socket) {
        free (ctx->socket);
    }
    if (ctx->errstr) {
        free (ctx->errstr);
    }
    free (ctx);
    return;
}


const char *
munge_ctx_strerror (munge_ctx_t ctx)
{
    assert (ctx != NULL);

    if (!ctx) {
        return (NULL);
    }
    if (ctx->errnum == EMUNGE_SUCCESS) {
        return (NULL);
    }
    if (ctx->errstr != NULL) {
        return (ctx->errstr);
    }
    return (munge_strerror (ctx->errnum));
}


munge_err_t
munge_ctx_get (munge_ctx_t ctx, munge_opt_t opt, ...)
{
    int             *p2int;
    char           **p2str;
    struct in_addr  *p2addr;
    time_t          *p2time;
    va_list          vargs;

    assert (ctx != NULL);

    if (!ctx) {
        return (EMUNGE_BAD_ARG);
    }
    ctx->errnum = EMUNGE_SUCCESS;
    if (ctx->errstr) {
        free (ctx->errstr);
        ctx->errstr = NULL;
    }
    va_start (vargs, opt);
    switch (opt) {
        case MUNGE_OPT_CIPHER_TYPE:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->cipher;
            break;
        case MUNGE_OPT_ZIP_TYPE:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->zip;
            break;
        case MUNGE_OPT_MAC_TYPE:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->mac;
            break;
        case MUNGE_OPT_REALM:
            p2str = va_arg (vargs, char **);
            *p2str = ctx->realm;
            break;
        case MUNGE_OPT_TTL:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->ttl;
            break;
        case MUNGE_OPT_ADDR4:
            p2addr = va_arg (vargs, struct in_addr *);
            *p2addr = ctx->addr;
            break;
        case MUNGE_OPT_ENCODE_TIME:
            p2time = va_arg (vargs, time_t *);
            *p2time = ctx->time0;
            break;
        case MUNGE_OPT_DECODE_TIME:
            p2time = va_arg (vargs, time_t *);
            *p2time = ctx->time1;
            break;
        case MUNGE_OPT_SOCKET:
            p2str = va_arg (vargs, char **);
            *p2str = ctx->socket;
            break;
        default:
            ctx->errnum = EMUNGE_BAD_ARG;
            break;
    }
    va_end (vargs);
    return (ctx->errnum);
}


munge_err_t
munge_ctx_set (munge_ctx_t ctx, munge_opt_t opt, ...)
{
    char        *str;
    char        *p;
    int          i;
    va_list      vargs;

    assert (ctx != NULL);

    if (!ctx) {
        return (EMUNGE_BAD_ARG);
    }
    ctx->errnum = EMUNGE_SUCCESS;
    if (ctx->errstr) {
        free (ctx->errstr);
        ctx->errstr = NULL;
    }
    va_start (vargs, opt);
    switch (opt) {
        case MUNGE_OPT_CIPHER_TYPE:
            ctx->cipher = va_arg (vargs, int);
            break;
        case MUNGE_OPT_ZIP_TYPE:
            ctx->zip = va_arg (vargs, int);
            break;
        case MUNGE_OPT_MAC_TYPE:
            ctx->mac = va_arg (vargs, int);
            break;
        case MUNGE_OPT_REALM:
            str = va_arg (vargs, char *);
            if (!str)
                p = NULL;
            else if (!(p = strdup (str))) {
                ctx->errnum = EMUNGE_NO_MEMORY;
                break;
            }
            if (ctx->realm)
                free (ctx->realm);
            ctx->realm = p;
            break;
        case MUNGE_OPT_TTL:
            i = va_arg (vargs, int);
            ctx->ttl = (i < 0) ? -1 : i;
            /*  Note signed to unsigned conversion here.  */
            break;
        case MUNGE_OPT_SOCKET:
            str = va_arg (vargs, char *);
            if (!str)
                p = NULL;
            else if (!(p = strdup (str))) {
                ctx->errnum = EMUNGE_NO_MEMORY;
                break;
            }
            if (ctx->socket)
                free (ctx->socket);
            ctx->socket = p;
            break;
        case MUNGE_OPT_ADDR4:
            /* this option cannot be set; fall through to error case */
        case MUNGE_OPT_ENCODE_TIME:
            /* this option cannot be set; fall through to error case */
        case MUNGE_OPT_DECODE_TIME:
            /* this option cannot be set; fall through to error case */
        default:
            ctx->errnum = EMUNGE_BAD_ARG;
            break;
    }
    va_end (vargs);
    return (ctx->errnum);
}


/*****************************************************************************
 *  Internal (but still "Extern") Functions
 *****************************************************************************/

munge_err_t
_munge_ctx_set_err (munge_ctx_t ctx, munge_err_t e, char *s)
{
/*  If an error condition does not already exist, sets an error code [e]
 *    and string [s] to be returned via the munge context [ctx].
 *  If [s] is not NULL, that string (and _not_ a copy) will be stored
 *    and later free()'d by the context destructor.
 *  Returns the [ctx] error code and consumes the string [s].
 */
    if (ctx) {
        if ((ctx->errnum == EMUNGE_SUCCESS) && (e != EMUNGE_SUCCESS)) {
            ctx->errnum = e;
            assert (ctx->errstr == NULL);
            ctx->errstr = s;
            s = NULL;
        }
    }
    if (s) {
        free (s);
    }
    return (ctx->errnum);
}
