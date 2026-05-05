/*****************************************************************************
 *  Copyright (C) 2007-2026 Lawrence Livermore National Security, LLC.
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
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/


#ifndef MUNGE_COMMON_H
#define MUNGE_COMMON_H


#ifndef MAX
#  define MAX(a,b) ((a >= b) ? (a) : (b))
#endif /* MAX */

#ifndef MIN
#  define MIN(a,b) ((a <= b) ? (a) : (b))
#endif /* MIN */

#include <stdint.h>                     /* UINT32_MAX */
#include <sys/types.h>                  /* uid_t, gid_t */

#define UID_MAXIMUM     (UINT32_MAX - 1)
#define UID_SENTINEL    ((uid_t) -1)
#define GID_MAXIMUM     (UINT32_MAX - 1)
#define GID_SENTINEL    ((gid_t) -1)


#endif /* MUNGE_COMMON_H */
