/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2003-2006 The Regents of the University of California.
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


#ifndef MUNGE_COMMON_H
#define MUNGE_COMMON_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include "auth_policy.h"
#include "fd.h"
#include "license.h"
#include "log.h"
#include "m_msg.h"
#include "munge_defs.h"
#include "posignal.h"
#include "str.h"


#if HAVE_BZLIB_H && HAVE_LIBBZ2
#  define HAVE_PKG_BZLIB 1
#endif

#if HAVE_ZLIB_H && HAVE_LIBZ
#  define HAVE_PKG_ZLIB 1
#endif

#ifndef MAX
#  define MAX(a,b) ((a >= b) ? (a) : (b))
#endif /* !MAX */

#ifndef MIN
#  define MIN(a,b) ((a <= b) ? (a) : (b))
#endif /* !MIN */


#endif /* !MUNGE_COMMON_H */
