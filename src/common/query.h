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


#ifndef MUNGE_QUERY_H
#define MUNGE_QUERY_H

#include <unistd.h>


int query_uid (const char *user, uid_t *uid_ptr);
/*
 *  Queries for the User ID using the [user] string which can specify the
 *    user name or UID number.
 *  Returns 0 on success with the UID stored at [uid_ptr] (if non-NULL).
 *    Returns -1 on error without updating [uid_ptr].
 */

int query_gid (const char *group, gid_t *gid_ptr);
/*
 *  Queries for the Group ID using the [group] string which can specify the
 *    group name or GID number.
 *  Returns 0 on success with the GID stored at [gid_ptr] (if non-NULL).
 *    Returns -1 on error without updating [gid_ptr].
 */


#endif /* !MUNGE_QUERY_H */
