/*****************************************************************************
 *  Copyright (C) 2007-2025 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
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

void log_close_file (void);

int log_open_syslog (const char *identity, int facility);

void log_close_syslog (void);

void log_close_all (void);

void log_err (int status, int priority, const char *format, ...);

void log_errno (int status, int priority, const char *format, ...);

void log_msg (int priority, const char *format, ...);

void log_err_or_warn (int got_force, const char *format, ...);


#endif /* !LOG_H */
