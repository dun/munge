/*****************************************************************************
 *  $Id: common.h,v 1.6 2004/04/03 21:53:00 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
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


#ifndef MUNGE_COMMON_H
#define MUNGE_COMMON_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
                                                                                
#include "fd.h"
#include "license.h"
#include "log.h"
#include "munge_defs.h"
#include "munge_msg.h"
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
