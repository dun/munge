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
#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <munge.h>
#include "ctx.h"
#include "munge_defs.h"


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

munge_ctx_t
munge_ctx_create (void)
{
    munge_ctx_t ctx;

    if (!(ctx = malloc (sizeof (*ctx)))) {
        return (NULL);
    }
    ctx->cipher = MUNGE_CIPHER_DEFAULT;
    ctx->mac = MUNGE_MAC_DEFAULT;
    ctx->zip = MUNGE_ZIP_DEFAULT;
    ctx->realm_str = NULL;
    ctx->ttl = MUNGE_TTL_DEFAULT;
    ctx->addr.s_addr = 0;
    ctx->time0 = 0;
    ctx->time1 = 0;
    ctx->auth_uid = MUNGE_UID_ANY;
    ctx->auth_gid = MUNGE_GID_ANY;
    ctx->socket_str = strdup (MUNGE_SOCKET_NAME);
    ctx->error_num = EMUNGE_SUCCESS;
    ctx->error_str = NULL;

    if (!ctx->socket_str) {
        munge_ctx_destroy (ctx);
        return (NULL);
    }
    return (ctx);
}


munge_ctx_t
munge_ctx_copy (munge_ctx_t src)
{
    munge_ctx_t dst;

    if (!src) {
        return (NULL);
    }
    if (!(dst = malloc (sizeof (*dst)))) {
        return (NULL);
    }
    *dst = *src;
    /*
     *  Since struct assignment is a shallow copy, first reset all strings.
     *    This protects against calling munge_ctx_destroy (dst) on error.
     *    If any of these still referenced the src strings at that time,
     *    those strings would erroneously be free()d -- thereby corrupting
     *    the src ctx by mistake.
     */
    dst->realm_str = NULL;
    dst->socket_str = NULL;
    dst->error_str = NULL;
    /*
     *  Reset the error condition.
     */
    dst->error_num = EMUNGE_SUCCESS;
    /*
     *  Copy the src strings.
     */
    if ((src->realm_str) && !(dst->realm_str = strdup (src->realm_str))) {
        goto err;
    }
    if (!(dst->socket_str = strdup (src->socket_str))) {
        goto err;
    }
    return (dst);

err:
    munge_ctx_destroy (dst);
    return (NULL);
}


void
munge_ctx_destroy (munge_ctx_t ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->realm_str) {
        free (ctx->realm_str);
    }
    if (ctx->socket_str) {
        free (ctx->socket_str);
    }
    if (ctx->error_str) {
        free (ctx->error_str);
    }
    free (ctx);
    return;
}


const char *
munge_ctx_strerror (munge_ctx_t ctx)
{
    if (!ctx) {
        return (NULL);
    }
    if (ctx->error_num == EMUNGE_SUCCESS) {
        return (NULL);
    }
    if (ctx->error_str != NULL) {
        return (ctx->error_str);
    }
    return (munge_strerror (ctx->error_num));
}


munge_err_t
munge_ctx_get (munge_ctx_t ctx, int opt, ...)
{
    int             *p2int;
    char           **p2str;
    struct in_addr  *p2addr;
    time_t          *p2time;
    uid_t           *p2uid;
    gid_t           *p2gid;
    va_list          vargs;

    if (!ctx) {
        return (EMUNGE_BAD_ARG);
    }
    ctx->error_num = EMUNGE_SUCCESS;
    if (ctx->error_str) {
        free (ctx->error_str);
        ctx->error_str = NULL;
    }
    va_start (vargs, opt);
    switch (opt) {
        case MUNGE_OPT_CIPHER_TYPE:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->cipher;
            break;
        case MUNGE_OPT_MAC_TYPE:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->mac;
            break;
        case MUNGE_OPT_ZIP_TYPE:
            p2int = va_arg (vargs, int *);
            *p2int = ctx->zip;
            break;
        case MUNGE_OPT_REALM:
            p2str = va_arg (vargs, char **);
            *p2str = ctx->realm_str;
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
            *p2str = ctx->socket_str;
            break;
        case MUNGE_OPT_UID_RESTRICTION:
            p2uid = va_arg (vargs, uid_t *);
            *p2uid = ctx->auth_uid;
            break;
        case MUNGE_OPT_GID_RESTRICTION:
            p2gid = va_arg (vargs, gid_t *);
            *p2gid = ctx->auth_gid;
            break;
        default:
            ctx->error_num = EMUNGE_BAD_ARG;
            break;
    }
    va_end (vargs);
    return (ctx->error_num);
}


munge_err_t
munge_ctx_set (munge_ctx_t ctx, int opt, ...)
{
    char        *str;
    char        *p;
    int          i;
    va_list      vargs;

    if (!ctx) {
        return (EMUNGE_BAD_ARG);
    }
    ctx->error_num = EMUNGE_SUCCESS;
    if (ctx->error_str) {
        free (ctx->error_str);
        ctx->error_str = NULL;
    }
    va_start (vargs, opt);
    switch (opt) {
        case MUNGE_OPT_CIPHER_TYPE:
            ctx->cipher = va_arg (vargs, int);
            break;
        case MUNGE_OPT_MAC_TYPE:
            ctx->mac = va_arg (vargs, int);
            break;
        case MUNGE_OPT_ZIP_TYPE:
            ctx->zip = va_arg (vargs, int);
            break;
        case MUNGE_OPT_REALM:
            str = va_arg (vargs, char *);
            if (!str) {
                p = NULL;
            }
            else if (strlen (str) > 255) {
                ctx->error_num = EMUNGE_BAD_LENGTH;
                break;
            }
            else if (!(p = strdup (str))) {
                ctx->error_num = EMUNGE_NO_MEMORY;
                break;
            }
            if (ctx->realm_str) {
                free (ctx->realm_str);
            }
            ctx->realm_str = p;
            break;
        case MUNGE_OPT_TTL:
            i = va_arg (vargs, int);
            ctx->ttl = (i == -1) ? MUNGE_TTL_MAXIMUM : i;
            break;
        case MUNGE_OPT_SOCKET:
            str = va_arg (vargs, char *);
            if (!str) {
                p = NULL;
            }
            else if (!(p = strdup (str))) {
                ctx->error_num = EMUNGE_NO_MEMORY;
                break;
            }
            if (ctx->socket_str) {
                free (ctx->socket_str);
            }
            ctx->socket_str = p;
            break;
        case MUNGE_OPT_UID_RESTRICTION:
            ctx->auth_uid = va_arg (vargs, uid_t);
            break;
        case MUNGE_OPT_GID_RESTRICTION:
            ctx->auth_gid = va_arg (vargs, gid_t);
            break;
        case MUNGE_OPT_ADDR4:
            /* this option cannot be set; fall through to error case */
        case MUNGE_OPT_ENCODE_TIME:
            /* this option cannot be set; fall through to error case */
        case MUNGE_OPT_DECODE_TIME:
            /* this option cannot be set; fall through to error case */
        default:
            ctx->error_num = EMUNGE_BAD_ARG;
            break;
    }
    va_end (vargs);
    return (ctx->error_num);
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
        if ((ctx->error_num == EMUNGE_SUCCESS) && (e != EMUNGE_SUCCESS)) {
            ctx->error_num = e;
            assert (ctx->error_str == NULL);
            ctx->error_str = s;
            s = NULL;
        }
        else {
            e = ctx->error_num;
        }
    }
    if (s) {
        free (s);
    }
    return (e);
}
