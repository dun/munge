/*****************************************************************************
 *  $Id: dprintf.h,v 1.1 2003/04/08 18:16:16 dun Exp $
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
 *****************************************************************************/


#ifndef DPRINTF_H
#define DPRINTF_H


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */


/*  DPRINTF ((level, format, ...))
 *    A wrapper for dprintf() allowing it to be removed from production code.
 */
#ifndef NDEBUG
#  define DPRINTF(args) dprintf args
#else /* NDEBUG */
#  define DPRINTF(args)
#endif /* NDEBUG */


void dprintf (int level, const char *format, ...);
/*
 *  Similar to printf, except output is always to stderr and only done
 *    when 'level' is less than or equal to the "DEBUG" env var.
 *    Thus, level=1 messages are of the highest importance.
 */


#endif /* !DPRINTF_H */
