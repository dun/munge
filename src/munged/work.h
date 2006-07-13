/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2004-2006 The Regents of the University of California.
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


#ifndef WORK_H
#define WORK_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct work * work_p;

typedef void (*work_func_t) (void *);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

work_p work_init (work_func_t f, int n_threads);
/*
 *  Initializes the work crew comprised of [n_threads] workers.
 *    The work function [f] will be invoked to process each work element
 *    queued by work_queue().
 *  Returns a ptr to the work crew, or NULL on error (with errno set).
 */

void work_fini (work_p wp, int do_wait);
/*
 *  Stops the work crew [wp], cancelling all worker threads and releasing
 *    associated resources.  If [do_wait] is non-zero, all currently-queued
 *    work will be processed before the work crew is stopped; new work is
 *    prevented from being added to the queue during this time.
 */

int work_queue (work_p wp, void *work);
/*
 *  Queues the [work] element for processing by the work crew [wp].
 *    The [work] will be passed to the function specified during work_init().
 *  Returns 0 on success, or -1 on error (with errno set).
 */

void work_wait (work_p wp);
/*
 *  Waits until all queued work is processed by the work crew [wp].
 */


#endif /* WORK_H */
