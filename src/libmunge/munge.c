/*****************************************************************************
 *  $Id: munge.c,v 1.5 2003/02/17 02:29:41 dun Exp $
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


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>


/***********
 *  Notes  *
 ***********/

/*  Yeah, this is ugly code.  I don't care.
 */


/***************
 *  Constants  *
 ***************/

#define MUNGE_DEFAULT_TTL       60
#define MUNGE_PREFIX            "MUNGE"


/************
 *  Macros  *
 ************/

#ifndef MAX
#  define MAX(x,y) (((x) >= (y)) ? (x) : (y))
#endif /* !MAX */

#ifndef MIN
#  define MIN(x,y) (((x) <= (y)) ? (x) : (y))
#endif /* !MIN */


static char b32e[] = "abcdefghijklmnopqrstuvwxyz012345";
static char b32d[128] = {-1};
static int base32_encode (char *dst, const char *src, int srclen);
static int base32_decode (char *dst, const char *src, int srclen);


munge_err_t
munge_encode (char **m, const munge_ctx_t *ctx, const void *buf, int len)
{
    int i, n;
    time_t now;
    char tmp[35];
    char *crd;
    int crdlen;
    char *p;
    unsigned short cksum = 0;

    assert(m);

    *m = NULL;

    if (len < 0) {
        len = 0;
    }
    if (time(&now) == ((time_t) -1)) {
        return(EMUNGE_SNAFU);
    }
    n = snprintf(tmp, sizeof(tmp), "%d:%d:%d:%d:",
        (int) now, getuid(), getgid(), len);
    if ((n < 0) || (n >= sizeof(tmp))) {
        return(EMUNGE_SNAFU);
    }
    for (i=0; i < strlen(tmp); i++) {
        cksum += tmp[i];
    }
    for (i=0, p=(char*)buf; i < len; i++) {
        cksum += p[i];
    }
    crdlen = strlen(MUNGE_PREFIX) + ((strlen(tmp) + len + 6) * 2) + 1;
    if (!(crd = malloc(crdlen))) {
        return(EMUNGE_NO_MEMORY);
    }
    strcpy(crd, MUNGE_PREFIX);
    p = strchr(crd, 0);
    p += base32_encode(p, tmp, strlen(tmp));
    if (len > 0) {
        p += base32_encode(p, buf, len);
    }
    snprintf(tmp, sizeof(tmp), ":%d", cksum);
    p += base32_encode(p, tmp, strlen(tmp));
    *p = '\0';
    *m = crd;
    return(EMUNGE_SUCCESS);
}


munge_err_t
munge_decode (const char *m, munge_ctx_t *ctx,
              void **pbuf, int *plen, uid_t *puid, gid_t *pgid)
{
    int n;
    char *tmpbuf;
    int tmplen;
    char *p, *q, *r;
    time_t now, then;
    unsigned short cksum0, cksum1;
    int len;
    uid_t uid;
    gid_t gid;

    assert(m);

    if (pbuf && plen) {
        *pbuf = NULL;
        *plen = 0;
    }
    if (time(&now) == ((time_t) -1)) {
        return(EMUNGE_SNAFU);
    }
    if (strncmp(m, MUNGE_PREFIX, strlen(MUNGE_PREFIX))) {
        return(EMUNGE_BAD_CRED);
    }
    m += strlen(MUNGE_PREFIX);

    tmplen = ((strlen(m) + 1) / 2) + 1;
    if (!(p = tmpbuf = malloc(tmplen))) {
        return(EMUNGE_NO_MEMORY);
    }
    n = base32_decode(tmpbuf, m, strlen(m));
    tmpbuf[n] = '\0';

    then = (time_t) atoi(p);
    if (abs(now - then) > MUNGE_DEFAULT_TTL) {
        free(tmpbuf);
        return(EMUNGE_CRED_EXPIRED);
    }

    if ((p = strchr(p, ':') + 1) == (void *) 1) {
        free(tmpbuf);
        return(EMUNGE_BAD_CRED);
    }
    uid = atoi(p);

    if ((p = strchr(p, ':') + 1) == (void *) 1) {
        free(tmpbuf);
        return(EMUNGE_BAD_CRED);
    }
    gid = atoi(p);

    if ((p = strchr(p, ':') + 1) == (void *) 1) {
        free(tmpbuf);
        return(EMUNGE_BAD_CRED);
    }
    len = atoi(p);

    if ((p = strchr(p, ':') + 1) == (void *) 1) {
        free(tmpbuf);
        return(EMUNGE_BAD_CRED);
    }

    q = p + len;
    if (*q != ':') {
        free(tmpbuf);
        return(EMUNGE_BAD_CRED);
    }
    cksum0 = atoi(q+1);
    for (r=tmpbuf, cksum1=0; r<q; r++) {
        cksum1 += *r;
    }
    if (cksum0 != cksum1) {
        free(tmpbuf);
        return(EMUNGE_BAD_CRED);
    }

    if (puid) {
        *puid = uid;
    }
    if (pgid) {
        *pgid = gid;
    }
    if (pbuf && plen) {
        *plen = len;
        if (!len) {
            *pbuf = NULL;
        }
        else {
            if (!(*pbuf = malloc(len + 1))) {
                free(tmpbuf);
                return(EMUNGE_NO_MEMORY);
            }
            memcpy(*pbuf, p, len);
            memset(*pbuf + len, 0, 1);          /* ensure buf is NUL-term'd */

        }
    }
    free(tmpbuf);
    return(EMUNGE_SUCCESS);
}


const char *
munge_strerror (munge_err_t errnum)
{
    switch (errnum) {
        case EMUNGE_SUCCESS:
            return("Success");
        case EMUNGE_SNAFU:
            return("Internal error");
        case EMUNGE_INVAL:
            return("Invalid argument");
        case EMUNGE_NO_MEMORY:
            return("Out of memory");
        case EMUNGE_OVERFLOW:
            return("Buffer overflow");
        case EMUNGE_NO_DAEMON:
            return("No response from munged");
        case EMUNGE_TIMEOUT:
            return("Timed-out with munged");
        case EMUNGE_PROTO:
            return("Protocol error with munged");
        case EMUNGE_BAD_CRED:
            return("Invalid credential");
        case EMUNGE_BAD_VERSION:
            return("Unrecognized version");
        case EMUNGE_BAD_CIPHER:
            return("Unsupported cipher");
        case EMUNGE_BAD_ZIP:
            return("Unsupported compression");
        case EMUNGE_BAD_MAC:
            return("Unsupported MAC");
        case EMUNGE_CRED_EXPIRED:
            return("Expired credential");
        case EMUNGE_CRED_REWOUND:
            return("Rewound credential");
        case EMUNGE_CRED_REPLAYED:
            return("Replayed credential");
        default:
            return("Unknown");
    }
    return(NULL);
}


static int
base32_encode (char *dst, const char *src, int srclen)
{
    int i;

    for (i=0; i<srclen; i++) {
        *dst++ = b32e[ (src[i] & 0xF0) >> 4 ];
        *dst++ = b32e[ (src[i] & 0x0F) ];
    }
    return(srclen * 2);
}


static int
base32_decode (char *dst, const char *src, int srclen)
{
    int i;

    if (b32d[0] == -1) {
        b32d[0] = 0;
        for (i=0; i<sizeof(b32e); i++) {
            b32d[ (int) b32e[i] ] = i;
        }
    }
    for (i=0; i<srclen; i+=2) {
        *dst++ = (b32d[ (int) src[i] ] << 4) + (b32d[ (int) src[i+1] ]);
    }
    return(srclen / 2);
}
