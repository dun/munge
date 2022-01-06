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
#include "daemonpipe.h"
#include "log.h"
#include "str.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define LOG_BUFFER_MAXLEN       1024
#define LOG_IDENTITY_MAXLEN     128
#define LOG_PREFIX_MAXLEN       9
#define LOG_TRUNC_SUFFIX        "+"


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct log_ctx {
    FILE *fp;
    int   got_init;
    int   got_syslog;
    int   got_fprintf_error;
    int   priority;
    int   options;
    char  id [LOG_IDENTITY_MAXLEN];
};


/*****************************************************************************
 *  Static Variables
 *****************************************************************************/

static struct log_ctx log_ctx = { NULL, 0, 0, 0, 0, 0, { '\0' } };


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static void _log_aux (int errnum, int priority, char *msgbuf, int msgbuflen,
        const char *format, va_list vargs);
static void _log_die (int status, int priority, const char *msg);
static char * _log_prefix (int priority);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

int
log_open_file (FILE *fp, const char *identity, int priority, int options)
{
    const char *p;

    if (!fp) {
        errno = EINVAL;
        return (-1);
    }
    if (ferror (fp)) {
        return (-1);
    }
    if (setvbuf (fp, NULL, _IONBF, 0) != 0) {   /* set stream unbuffered */
        return (-1);
    }
    log_ctx.fp = fp;
    memset (log_ctx.id, 0, sizeof (log_ctx.id));
    if (identity) {
        p = (p = strrchr (identity, '/')) ? p + 1 : identity;
        if (strlen (p) < sizeof (log_ctx.id)) {
            strcpy (log_ctx.id, p);
        }
    }
    log_ctx.priority = (priority > 0) ? priority : 0;
    log_ctx.options = options;
    log_ctx.got_init = 1;
    return (0);
}


void
log_close_file (void)
{
    if (log_ctx.fp) {
        (void) fclose (log_ctx.fp);
        log_ctx.fp = NULL;
    }
    return;
}


int
log_open_syslog (const char *identity, int facility)
{
    char *p;

    if (!identity) {
        errno = EINVAL;
        return (-1);
    }
    if ((p = strrchr (identity, '/'))) {
        identity = p + 1;
    }
    openlog (identity, LOG_NDELAY | LOG_PID, facility);
    log_ctx.got_syslog = 1;
    log_ctx.got_init = 1;
    return (0);
}


void
log_close_syslog (void)
{
    if (log_ctx.got_syslog) {
        closelog ();
        log_ctx.got_syslog = 0;
    }
    return;
}


void
log_close_all (void)
{
    log_close_file ();
    log_close_syslog ();
    return;
}


void
log_err (int status, int priority, const char *format, ...)
{
    va_list vargs;
    char    msg [LOG_BUFFER_MAXLEN];

    va_start (vargs, format);
    _log_aux (0, priority, msg, sizeof (msg), format, vargs);
    va_end (vargs);

    _log_die (status, priority, msg);
    assert (1);                         /* not reached */
}


void
log_errno (int status, int priority, const char *format, ...)
{
    va_list vargs;
    char    msg [LOG_BUFFER_MAXLEN];

    va_start (vargs, format);
    _log_aux (errno, priority, msg, sizeof (msg), format, vargs);
    va_end (vargs);

    _log_die (status, priority, msg);
    assert (1);                         /* not reached */
}


void
log_msg (int priority, const char *format, ...)
{
    va_list vargs;

    va_start (vargs, format);
    _log_aux (0, priority, NULL, 0, format, vargs);
    va_end (vargs);

    return;
}


void
log_err_or_warn (int got_force, const char *format, ...)
{
    va_list vargs;
    char    msg [LOG_BUFFER_MAXLEN];
    int     priority;

    priority = (got_force) ? LOG_WARNING : LOG_ERR;

    va_start (vargs, format);
    _log_aux (0, priority, msg, sizeof (msg), format, vargs);
    va_end (vargs);

    if (!got_force) {
        _log_die (1, priority, msg);
    }
    return;
}


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static void
_log_aux (int errnum, int priority, char *msgbuf, int msgbuflen,
        const char *format, va_list vargs)
{
    char  buf [LOG_BUFFER_MAXLEN];      /* message buffer                    */
    char *p;                            /* current position in msg buf       */
    char *sbuf;                         /* syslog portion of message buffer  */
    char *prefix;                       /* priority prefix message           */
    int   n;                            /* return value of num chars written */
    int   len;                          /* remaining len in buf includes nul */
    int   append_nl = 0;                /* set to 1 if trailing nl is needed */

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

    if ((!format) || (format [strlen (format) - 1] != '\n')) {
        append_nl = 1;
        --len;                          /* reserve space for trailing LF */
    }
    /*  Add identity string.
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
        n = strftimet (p, len, "%Y-%m-%d %H:%M:%S %z ", 0);
        if (n == 0) {
            len = 0;
        }
        else if (n > 0) {
            p += n;
            len -= n;
        }
    }
    /*  Add priority string.
     */
    if ((len > 0) && (log_ctx.options & LOG_OPT_PRIORITY)) {
        if ((prefix = _log_prefix (priority))) {
            int m = 1;
            if (log_ctx.options & LOG_OPT_JUSTIFY) {
                if ((m = LOG_PREFIX_MAXLEN + 1 - strlen (prefix)) < 0) {
                    m = 1;
                }
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
    if ((len > 0) && (format)) {
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
    /*  Add error string if:
     *    - an error occurred (defined by errno), and
     *    - the error string does not contain a trailing newline.
     */
    if ((len > 0) && (errnum) && (append_nl)) {
        n = snprintf (p, len, "%s%s",
            (format ? ": " : ""), strerror (errnum));
        if ((n < 0) || (n >= len)) {
            p += len - 1;
            len = 0;
        }
        else {
            p += n;
            len -= n;
        }
    }
    /*  Add truncation string if buffer was overrun.
     */
    if (len <= 0) {
        char *q;
        n = strlen (LOG_TRUNC_SUFFIX);
        q = buf + sizeof (buf) - 1 - append_nl - n;
        p = (p < q) ? p : q;
        strcpy (p, LOG_TRUNC_SUFFIX);
        p += n;
    }
    /*  Terminate buffer with trailing newline and terminating NUL.
     */
    if (append_nl) {
        *p++ = '\n';
    }
    *p = '\0';

    /*  Return error message string.
     */
    if (msgbuf && (msgbuflen > 0)) {
        if (sbuf) {
            strncpy (msgbuf, sbuf, msgbuflen);
            msgbuf[msgbuflen - 1] = '\0';
        }
        else {
            msgbuf[0] = '\0';
        }
    }
    /*  Log message.
     */
    if (log_ctx.got_syslog && sbuf) {
        syslog (priority, "%s", sbuf);
    }
    if (log_ctx.fp && (priority <= log_ctx.priority)) {
        errno = 0;
        if (fprintf (log_ctx.fp, "%s", buf) == EOF) {
            if (!log_ctx.got_fprintf_error) {
                syslog (LOG_ERR,
                    "Failed logfile write: %s: messages may have been dropped",
                    (errno != 0) ? strerror (errno) : "Unspecified error");
                log_ctx.got_fprintf_error = 1;
            }
        }
        else if (log_ctx.got_fprintf_error) {
            log_ctx.got_fprintf_error = 0;
        }
    }
    return;
}


static void
_log_die (int status, int priority, const char *msg)
{
    /*  If the daemonpipe is open between the (grand)child process and the
     *    parent process, relay the error message to the parent for output onto
     *    stderr.  But if the error message has already been written to stderr,
     *    simply relay the status without the message text.
     */
    (void) daemonpipe_write (status, priority,
            (log_ctx.fp != stderr) ? msg : NULL);

#ifndef NDEBUG
    /*  Generate core for debugging.
     */
    if ((status != EXIT_SUCCESS) && getenv ("DEBUG")) {
        abort ();
    }
#endif /* !NDEBUG */

    exit (status);
}


static char *
_log_prefix (int priority)
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
    assert (1);                         /* not reached */
}
