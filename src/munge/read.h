/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2008 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#ifndef MUNGE_READ_H
#define MUNGE_READ_H

#include <stdio.h>


int read_data_from_file (FILE *fp, void **buf, int *len);
/*
 *  Malloc()'s a buffer and reads data from file pointer [fp] into it,
 *    ensuring the buffer contains a terminating NUL.
 *  The reference parm [buf] is set to the address of the malloc'd buffer,
 *    and [len] is set to the length of the data (not including the
 *    terminating NUL character).
 *  Returns the number of bytes read on success; o/w, returns -1 on error
 *    (with errno set appropriately).
 *  Note that memory is only malloc'd on a return value >0.
 */

int read_data_from_string (const char *s, void **buf, int *len);
/*
 *  Malloc()'s a buffer and copies data from string [s] into it,
 *    ensuring the buffer contains a trailing newline and terminating NUL.
 *  The reference parm [buf] is set to the address of the malloc'd buffer,
 *    and [len] is set to the length of the string (not including the
 *    terminating NUL character).
 *  Returns the number of bytes read on success, 0 if [s] is NULL or empty,
 *    or -1 on error (with errno set appropriately).
 *  Note that memory is only malloc'd on a return value >0.
 */


#endif /* !MUNGE_READ_H */
