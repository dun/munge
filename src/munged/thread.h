/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2017 Lawrence Livermore National Security, LLC.
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


#ifndef LSD_THREAD_H
#define LSD_THREAD_H


#if WITH_PTHREADS
#  include <errno.h>
#  include <pthread.h>
#  include <stdlib.h>
#endif /* WITH_PTHREADS */


/*****************************************************************************
 *  Macros
 *****************************************************************************/

#if WITH_PTHREADS

#  ifdef WITH_LSD_FATAL_ERROR_FUNC
#    undef lsd_fatal_error
     extern void lsd_fatal_error (char *file, int line, char *mesg);
#  else /* !WITH_LSD_FATAL_ERROR_FUNC */
#    ifndef lsd_fatal_error
#      define lsd_fatal_error(file, line, mesg) (abort ())
#    endif /* !lsd_fatal_error */
#  endif /* !WITH_LSD_FATAL_ERROR_FUNC */

#  define lsd_mutex_init(pmutex)                                              \
     do {                                                                     \
         int e = pthread_mutex_init (pmutex, NULL);                           \
         if (e != 0) {                                                        \
             errno = e;                                                       \
             lsd_fatal_error (__FILE__, __LINE__, "mutex_init");              \
             abort ();                                                        \
         }                                                                    \
     } while (0)

#  define lsd_mutex_lock(pmutex)                                              \
     do {                                                                     \
         int e = pthread_mutex_lock (pmutex);                                 \
         if (e != 0) {                                                        \
             errno = e;                                                       \
             lsd_fatal_error (__FILE__, __LINE__, "mutex_lock");              \
             abort ();                                                        \
         }                                                                    \
     } while (0)

#  define lsd_mutex_unlock(pmutex)                                            \
     do {                                                                     \
         int e = pthread_mutex_unlock (pmutex);                               \
         if (e != 0) {                                                        \
             errno = e;                                                       \
             lsd_fatal_error (__FILE__, __LINE__, "mutex_unlock");            \
             abort ();                                                        \
         }                                                                    \
     } while (0)

#  define lsd_mutex_destroy(pmutex)                                           \
     do {                                                                     \
         int e = pthread_mutex_destroy (pmutex);                              \
         if (e != 0) {                                                        \
             errno = e;                                                       \
             lsd_fatal_error (__FILE__, __LINE__, "mutex_destroy");           \
             abort ();                                                        \
         }                                                                    \
     } while (0)

#  ifndef NDEBUG
     int lsd_mutex_is_locked (pthread_mutex_t *pmutex);
#  endif /* !NDEBUG */

#else /* !WITH_PTHREADS */

#  define lsd_mutex_init(mutex)
#  define lsd_mutex_lock(mutex)
#  define lsd_mutex_unlock(mutex)
#  define lsd_mutex_destroy(mutex)
#  define lsd_mutex_is_locked(mutex) (1)

#endif /* !WITH_PTHREADS */


#endif /* !LSD_THREAD_H */
