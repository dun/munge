/*****************************************************************************
 *  $Id: log.c,v 1.2 2003/02/18 19:46:19 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2001-2003 The Regents of the University of California.
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
 *****************************************************************************
 *  Refer to "log.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "log.h"


#define LOG_BUFFER_MAXLEN       1024
#define LOG_IDENTITY_MAXLEN     128
#define LOG_PREFIX_MAXLEN       9
#define LOG_TRUNC_STRING        "+"


struct log_ctx {
    FILE *fp;
    int   got_init;
    int   got_syslog;
    int   priority;
    int   options;
    char  id [LOG_IDENTITY_MAXLEN];
};

static struct log_ctx log_ctx = { NULL, 0, 0, 0, 0 };


static void log_aux (int priority, const char *format, va_list vargs);
static char * log_prefix (int priority);


void
dprintf (int level, const char *format, ...)
{
    static int debug_level = -1;
    va_list vargs;
    char *p;
    int i = 0;

    if (debug_level < 0) {
        if ((p = getenv ("DEBUG")))
            i = atoi (p);
        debug_level = (i > 0) ? i : 0;
    }
    if ((level > 0) && (level <= debug_level)) {
        va_start (vargs, format);
        vfprintf (stderr, format, vargs);
        va_end (vargs);
    }
    return;
}


int
log_open_file (FILE *fp, char *identity, int priority, int options)
{
    char *p;

    if (!fp) {
        if (log_ctx.fp)
            fclose (log_ctx.fp);                /* ignore errors on close */
        log_ctx.fp = NULL;
        log_ctx.got_init = 1;
        return (0);
    }
    if (ferror (fp))
        return (-1);
    if (setvbuf (fp, NULL, _IONBF, 0) != 0)     /* set stream unbuffered */
        return (-1);

    log_ctx.fp = fp;
    memset (log_ctx.id, 0, sizeof (log_ctx.id));
    if (identity) {
        p = (p = strrchr (identity, '/')) ? p + 1 : identity;
        if (strlen (p) < sizeof (log_ctx.id))
            strcpy (log_ctx.id, p);
    }
    log_ctx.priority = (priority > 0) ? priority : 0;
    log_ctx.options = options;
    log_ctx.got_init = 1;
    return (1);
}


int
log_open_syslog (char *identity, int facility)
{
    char *p;

    if ((p = strrchr (identity, '/')))
        identity = p + 1;

    if (identity) {
        openlog (identity, LOG_NDELAY | LOG_PID, facility);
        log_ctx.got_syslog = 1;
    }
    else {
        closelog ();
        log_ctx.got_syslog = 0;
    }
    log_ctx.got_init = 1;
    return (log_ctx.got_syslog);
}


void
log_err (int status, const char *format, ...)
{
    va_list vargs;

    va_start (vargs, format);
    log_aux (LOG_ERR, format, vargs);
    va_end (vargs);

#ifndef NDEBUG
    if ((status != EXIT_SUCCESS) && getenv ("DEBUG"))
        abort ();                       /* generate core for debugging */
#endif /* !NDEBUG */
    exit (status);
}


void
log_msg (int priority, const char *format, ...)
{
    va_list vargs;

    va_start (vargs, format);
    log_aux (priority, format, vargs);
    va_end (vargs);

    return;
}


static void
log_aux (int priority, const char *format, va_list vargs)
{
    char  buf [LOG_BUFFER_MAXLEN];      /* message buffer                    */
    char *p;                            /* current position in msg buf       */
    char *sbuf;                         /* syslog portion of message buffer  */
    char *prefix;                       /* priority prefix message           */
    int  n;                             /* return value of num chars written */
    int  len;                           /* remaining len in buf includes \0  */
    int  append_nl = 0;                 /* set to 1 if trailing nl is needed */

    /*  If no log has been specified, output log msgs to stderr.
     */
    if (!log_ctx.got_init) {
        log_ctx.fp = stderr;
        log_ctx.options = 0;
        log_ctx.priority = LOG_DEBUG;
        log_ctx.got_init = 1;
    }
    p = buf;
    sbuf = NULL;
    len = sizeof (buf);

    if (format [strlen (format) - 1] != '\n') {
        append_nl = 1;
        --len;                          /* reserve space for trailing LF */
    }
    /*  Add identity.
     */
    if (log_ctx.id [0] != '\0') {
        n = snprintf (p, len, "%s: ", log_ctx.id);
        if ((n < 0) || (n >= len)) {
            p += len - 1;
            len = 0;
        }
        else {
            p += n;
            len -= n;
        }
    }
    /*  Add timestamp.
     */
    if ((len > 0) && (log_ctx.options & LOG_OPT_TIMESTAMP)) {
        time_t t;
        struct tm *tm_ptr;
        if (time (&t) != ((time_t) -1)) {
#if HAVE_LOCALTIME_R
            struct tm tm;
            tm_ptr = localtime_r (&t, &tm);
#else  /* !HAVE_LOCALTIME_R */
            tm_ptr = localtime (&t);
#endif /* !HAVE_LOCALTIME_R */
            if (tm_ptr != NULL) {
                n = strftime (p, len, "%Y-%m-%d %H:%M:%S ", tm_ptr);
                if ((n <= 0) || (n >= len)) {
                    /* do not update p since strftime output is undefined */
                    len = 0;
                }
                else {
                    p += n;
                    len -= n;
                }
            }
        }
    }
    /*  Add priority string.
     */
    if ((len > 0) && (log_ctx.options & LOG_OPT_PRIORITY)) {
        if ((prefix = log_prefix (priority))) {
            int m = 1;
            if (log_ctx.options & LOG_OPT_JUSTIFY) {
                if ((m = LOG_PREFIX_MAXLEN + 1 - strlen (prefix)) < 0)
                    m = 1;
            }
            n = snprintf (p, len, "%s:%*c", prefix, m, 0x20);
            if ((n < 0) || (n >= len)) {
                p += len - 1;
                len = 0;
            }
            else {
                p += n;
                len -= n;
            }
        }
    }
    /*  Add actual message.
     */
    if (len > 0) {
        sbuf = p;
        n = vsnprintf (p, len, format, vargs);
        if ((n < 0) || (n >= len)) {
            p += len - 1;
            len = 0;
        }
        else {
            p += n;
            len -= n;
        }
    }
    /*  Add truncation string if buffer was overrun along the way.
     */
    if (len <= 0) {
        char *q;
        n = strlen (LOG_TRUNC_STRING);
        q = buf + sizeof (buf) - 1 - append_nl - n;
        p = (p < q) ? p : q;
        strcpy (p, LOG_TRUNC_STRING);
        p += n;
    }
    /*  Terminate the buffer with a trailing newline and terminating NUL.
     */
    if (append_nl)
        *p++ = '\n';
    *p = '\0';

    /*  Log this!
     */
    if (log_ctx.got_syslog && sbuf) {
        syslog (priority, "%s", sbuf);
    }
    if (log_ctx.fp && (priority <= log_ctx.priority)) {
        if (fprintf (log_ctx.fp, "%s", buf) == EOF) {
            syslog (LOG_CRIT, "Logging stopped due to error");
            log_ctx.fp = NULL;
        }
    }
    return;
}


static char *
log_prefix (int priority)
{
    switch (priority) {
        case LOG_EMERG:
            return ("Emergency");
        case LOG_ALERT:
            return ("Alert");
        case LOG_CRIT:
            return ("Critical");
        case LOG_ERR:
            return ("Error");
        case LOG_WARNING:
            return ("Warning");
        case LOG_NOTICE:
            return ("Notice");
        case LOG_INFO:
            return ("Info");
        case LOG_DEBUG:
            return ("Debug");
        default:
            return ("Unknown");
    }
    /* not reached */
}
