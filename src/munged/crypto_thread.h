/*****************************************************************************
 *  $Id: crypto_thread.h,v 1.4 2004/04/03 21:53:00 dun Exp $
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


#ifndef CRYPTO_THREAD_H
#define CRYPTO_THREAD_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#if 1
/*
 *  This ifdef used to test for HAVE_LIBPTHREAD, but this define has been
 *    removed now that configure checks to see if it can link against pthreads,
 *    and fails if it cannot.
 */
#define _CRYPTO_THREAD_FUNCTIONS 1
int crypto_thread_init (void);
int crypto_thread_fini (void);

#else  /* 0 */

#define _CRYPTO_THREAD_FUNCTIONS 0
#define crypto_thread_init()
#define crypto_thread_fini()

#endif /* 0 */


#endif /* !CRYPTO_THREAD_H */
