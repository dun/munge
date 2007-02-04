/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2002-2007 The Regents of the University of California.
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


#ifndef TIMER_H
#define TIMER_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <time.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef void (*callback_f) (void *arg);
/*
 *  Function prototype for a timer callback function.
 */


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

void timer_init (void);
/*
 *  Initialize the timer thread.  Timers can be set before calling this
 *    routine, but expired timers will not be processed until it is called.
 */

void timer_fini (void);
/*
 *  Cancels the timer thread and all pending timers.
 */

int timer_set_absolute (callback_f cb, void *arg, const struct timespec *tsp);
/*
 *  Sets a timer to expire at the absolute time specified by [tsp].
 *    At expiration, the callback function [cb] will be invoked with [arg].
 *  Returns a timer ID > 0, or -1 on error (with errno set appropriately).
 */

int timer_set_relative (callback_f cb, void *arg, int ms);
/*
 *  Sets a timer to expire at [ms] milliseconds past the current time.
 *    At expiration, the callback function [cb] will be invoked with [arg].
 *  Returns a timer ID > 0, or -1 on error (with errno set appropriately).
 */

int timer_cancel (int id);
/*
 *  Cancels the timer specified by [id] before it expires.
 *  Returns 1 on success, 0 if the [id] did not match an active timer,
 *    and -1 on error (with errno set appropriately).
 */


#endif /* !TIMER_H */
