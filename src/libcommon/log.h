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


int log_open_file (FILE *fp, const char *identity, int priority, int options);
/*
 *  If [fp] is non-NULL, log messages at the [priority] level and higher
 *    (ie, below) to the specified file stream.
 *  If [identity] is non-NULL, its trailing "filename" component will
 *    be prepended to each message.
 *  The [options] parameter is a bitwise-OR of any "LOG_OPT_" defines
 *    specified above.
 *  Messages can be concurrently logged to syslog and one file stream.
 *  Returns 0 if the file is opened, or -1 on error;
 *    on error, the previous file stream remains open.
 */

void log_close_file (void);
/*
 *  Close the logging file stream (if open).
 */

int log_open_syslog (const char *identity, int facility);
/*
 *  If [identity] is non-NULL, log messages to syslog at the specified
 *    [facility] (cf, syslog(3)) prepending the trailing "filename" component
 *    of [identity] to each message.
 *  Messages can be concurrently logged to syslog and one file stream.
 *  Returns 0 on success, -1 on error.
 */

void log_close_syslog (void);
/*
 *  Closes the file descriptor used to write to the system logger (if open).
 */

void log_close_all (void);
/*
 *  Closes all logging devices that are open.
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

void log_err_or_warn (int got_force, const char *format, ...);
/*
 *  If [got_force] is false, log a fatal error message with the printf-style
 *    [format] string.
 *  If [got_force] is true, the fatal error is converted into a non-fatal
 *    warning.
 */


#endif /* !LOG_H */
