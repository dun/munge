/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2001-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory.
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
 *****************************************************************************/


#ifndef LOG_H
#define LOG_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <syslog.h>


#define LOG_OPT_NONE            0x00
#define LOG_OPT_JUSTIFY         0x01    /* justify priority str field width  */
#define LOG_OPT_PRIORITY        0x02    /* add priority string to message    */
#define LOG_OPT_TIMESTAMP       0x04    /* add timestamp to message          */


int log_open_file (FILE *fp, char *identity, int priority, int options);
/*
 *  If [fp] is non-NULL, log messages at the [priority] level and higher
 *    (ie, below) to the specified file stream; o/w, disable logging to file.
 *  If [identity] is non-NULL, its trailing "filename" component will
 *    be prepended to each message.
 *  The [options] parameter is a bitwise-OR of any "LOG_OPT_" defines
 *    specified above.
 *  Messages can be concurrently logged to syslog and one file stream.
 *  Returns 1 if the file is opened, 0 if closed, or -1 on error;
 *    on error, the previous file stream remains open.
 */

int log_open_syslog (char *identity, int facility);
/*
 *  If [identity] is non-NULL, log messages to syslog at the specified
 *    [facility] (cf, syslog(3)) prepending the trailing "filename" component
 *    of [identity] to each message; o/w, disable logging to syslog.
 *  Messages can be concurrently logged to syslog and one file stream.
 *  Returns 1 if the syslog is opened, or 0 if closed.
 */

void log_set_err_pipe (int fd);
/*
 *  Sets the file-descriptor for the write-half of the daemonize pipe
 *    connecting the original parent process to the forked grandchild process
 *    under which the daemon will continue running.
 *  If set (ie, fd >= 0), log_err() & log_errno() will return an error status
 *    and error message string back to the original parent process.
 */

void log_err (int status, int priority, const char *format, ...);
/*
 *  Logs a fatal message at the specified [priority] level according to
 *    the printf-style [format] string, after which it exits the program
 *    with the specified [status] value.
 */

void log_errno (int status, int priority, const char *format, ...);
/*
 *  Logs a fatal message at the specified [priority] level according to
 *    the printf-style [format] string, after which it exits the program
 *    with the specified [status] value.
 *  An error string will be appended to the message if the format string
 *    is not terminated with a newline and errno is non-zero.
 */

void log_msg (int priority, const char *format, ...);
/*
 *  Logs a non-fatal message at the specified [priority] level according to
 *    the printf-style [format] string.
 */


#endif /* !LOG_H */
