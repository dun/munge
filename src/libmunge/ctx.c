/*****************************************************************************
 *  $Id: ctx.c,v 1.1 2003/04/08 18:16:16 dun Exp $
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
#include "munge_defs.h"


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
    ctx->ttl = MUNGE_TTL_DEFAULT;
    ctx->realm = NULL;
    ctx->time0 = 0;
    ctx->time1 = 0;
    ctx->socket = strdup (MUNGE_SOCKET_NAME);
    ctx->status = EMUNGE_SUCCESS;
    ctx->error = NULL;

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
        memset (ctx->realm, 0, strlen (ctx->realm));
        free (ctx->realm);
    }
    if (ctx->socket) {
        memset (ctx->socket, 0, strlen (ctx->socket));
        free (ctx->socket);
    }
    if (ctx->error) {
        memset (ctx->error, 0, strlen (ctx->error));
        free (ctx->error);
    }
    memset (ctx, 0, sizeof (*ctx));
    free (ctx);
    return;
}


const char *
munge_ctx_err (munge_ctx_t ctx)
{
    assert (ctx != NULL);

    if (ctx->status == EMUNGE_SUCCESS)
        return (NULL);
    if (ctx->error)
        return (ctx->error);
    return (munge_strerror (ctx->status));
}


munge_err_t
munge_ctx_get (munge_ctx_t ctx, munge_opt_t opt, ...)
{
    int         *p2int;
    char       **p2str;
    time_t      *p2time;
    va_list      vargs;

    assert (ctx != NULL);

    if (!ctx) {
        return (EMUNGE_BAD_ARG);
    }
    ctx->status = EMUNGE_SUCCESS;
    if (ctx->error) {
        free (ctx->error);
        ctx->error = NULL;
    }
    va_start (vargs, opt);
    switch (opt) {
        case MUNGE_OPT_CIPHER:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->cipher;
            break;
        case MUNGE_OPT_ZIP:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->zip;
            break;
        case MUNGE_OPT_MAC:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->mac;
            break;
        case MUNGE_OPT_TTL:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->ttl;
            break;
        case MUNGE_OPT_REALM:
            p2str = va_arg (vargs, char **);
            *p2str = ctx->realm;
            break;
        case MUNGE_OPT_TIME_ENCODE:
            p2time = va_arg (vargs, time_t *);
            *p2time = ctx->time0;
            break;
        case MUNGE_OPT_TIME_DECODE:
            p2time = va_arg (vargs, time_t *);
            *p2time = ctx->time1;
            break;
        case MUNGE_OPT_SOCKET:
            p2str = va_arg (vargs, char **);
            *p2str = ctx->socket;
            break;
        default:
            ctx->status = EMUNGE_BAD_ARG;
            break;
    }
    va_end (vargs);
    return (ctx->status);
}


munge_err_t
munge_ctx_set (munge_ctx_t ctx, munge_opt_t opt, ...)
{
    char        *str;
    char        *p;
    va_list      vargs;

    assert (ctx != NULL);

    if (!ctx) {
        return (EMUNGE_BAD_ARG);
    }
    ctx->status = EMUNGE_SUCCESS;
    if (ctx->error) {
        free (ctx->error);
        ctx->error = NULL;
    }
    va_start (vargs, opt);
    switch (opt) {
        case MUNGE_OPT_CIPHER:
            ctx->cipher = va_arg (vargs, int);
            break;
        case MUNGE_OPT_ZIP:
            ctx->zip = va_arg (vargs, int);
            break;
        case MUNGE_OPT_MAC:
            ctx->mac = va_arg (vargs, int);
            break;
        case MUNGE_OPT_TTL:
            ctx->ttl = va_arg (vargs, int);
            break;
        case MUNGE_OPT_REALM:
            str = va_arg (vargs, char *);
            if (!str)
                p = NULL;
            else if (!(p = strdup (str))) {
                ctx->status = EMUNGE_NO_MEMORY;
                break;
            }
            if (ctx->realm)
                free (ctx->realm);
            ctx->realm = p;
            break;
        case MUNGE_OPT_TIME_ENCODE:
            ctx->time0 = va_arg (vargs, time_t);
            break;
        case MUNGE_OPT_TIME_DECODE:
            ctx->time1 = va_arg (vargs, time_t);
            break;
        case MUNGE_OPT_SOCKET:
            str = va_arg (vargs, char *);
            if (!str)
                p = NULL;
            else if (!(p = strdup (str))) {
                ctx->status = EMUNGE_NO_MEMORY;
                break;
            }
            if (ctx->socket)
                free (ctx->socket);
            ctx->socket = p;
            break;
        default:
            ctx->status = EMUNGE_BAD_ARG;
            break;
    }
    va_end (vargs);
    return (ctx->status);
}
