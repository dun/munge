/*****************************************************************************
 *  $Id: posignal.c,v 1.2 2004/04/03 01:12:06 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-155910.
 *
 *  Copyright (C) 2001-2004 The Regents of the University of California.
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
 *****************************************************************************
 *  Refer to "posignal.h" for documentation on public functions.
 *****************************************************************************/


#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */


#include <errno.h>
#include <signal.h>
#include "posignal.h"


sigfun_t *
posignal (int signum, sigfun_t *f)
{
/*  A wrapper for the historical signal() function to do things the Posix way.
 *  cf. Stevens UNPv1 figure 5.6.
 */
    struct sigaction act0, act1;

    act1.sa_handler = f;
    sigemptyset (&act1.sa_mask);
    act1.sa_flags = 0;

#if 0
    if (signum == SIGALRM) {
#ifdef SA_INTERRUPT
        act1.sa_flags |= SA_INTERRUPT;  /* SunOS 4.x */
#endif /* SA_INTERRUPT */
    }
    else {
#ifdef SA_RESTART
        act1.sa_flags |= SA_RESTART;    /* SVR4, 4.4BSD */
#endif /* SA_RESTART */
    }
#endif /* 0 */

    if (sigaction (signum, &act1, &act0) < 0)
        return (SIG_ERR);
    return (act0.sa_handler);
}
