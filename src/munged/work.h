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
 *  Stops the work crew [wp], canceling all worker threads and releasing
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
