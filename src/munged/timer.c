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
 *****************************************************************************
 *  Based on ideas from:
 *  - David R. Butenhof's "Programming with POSIX Threads" (Section 3.3.4)
 *  - Jon C. Snader's "Effective TCP/IP Programming" (Tip #20)
 *****************************************************************************
 *  Refer to "timer.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>
#include "clock.h"
#include "log.h"
#include "thread.h"
#include "timer.h"


/*****************************************************************************
 *  Private Data Types
 *****************************************************************************/

struct timer {
    long               id;              /* timer ID                          */
    struct timespec    ts;              /* expiration time                   */
    callback_f         f;               /* callback function                 */
    void              *arg;             /* callback function arg             */
    struct timer      *next;            /* next timer in list                */
};

typedef struct timer * timer_p;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void * _timer_thread (void *arg);

static void _timer_thread_cleanup (void *arg);

static timer_p _timer_alloc (void);


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

static pthread_t       _timer_tid = 0;
static pthread_cond_t  _timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t _timer_mutex = PTHREAD_MUTEX_INITIALIZER;

/*  The _timer_id is the ID of the last timer that was set.
 */
static long            _timer_id = 0;

/*  The _timer_active list contains timers waiting to be dispatched, sorted in
 *    order of increasing timespecs; the list head is the next timer to expire.
 */
static timer_p         _timer_active = NULL;

/*  The _timer_inactive list contains timers that have been dispatched and can
 *    be reused without allocating more memory.
 */
static timer_p         _timer_inactive = NULL;


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
timer_init (void)
{
    pthread_attr_t tattr;
    size_t         stacksize = 256 * 1024;

    if (_timer_tid != 0) {
        return;
    }
    if ((errno = pthread_attr_init (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to init timer thread attribute");
    }
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    if ((errno = pthread_attr_setstacksize (&tattr, stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to set timer thread stacksize");
    }
    if ((errno = pthread_attr_getstacksize (&tattr, &stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to get timer thread stacksize");
    }
    log_msg (LOG_DEBUG, "Set timer thread stacksize to %d", (int) stacksize);
#endif /* _POSIX_THREAD_ATTR_STACKSIZE */

    if ((errno = pthread_create (&_timer_tid, &tattr, _timer_thread, NULL))
            != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create timer thread");
    }
    if ((errno = pthread_attr_destroy (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to destroy timer thread attribute");
    }
    return;
}


void
timer_fini (void)
{
    void    *result;
    timer_p *t_prev_ptr;
    timer_p  t;

    if (_timer_tid == 0) {
        return;
    }
    if ((errno = pthread_cancel (_timer_tid)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to cancel timer thread");
    }
    if ((errno = pthread_join (_timer_tid, &result)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to join timer thread");
    }
    if (result != PTHREAD_CANCELED) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Timer thread was not canceled");
    }
    _timer_tid = 0;

    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock timer mutex");
    }
    /*  Cancel pending timers by moving active timers to the inactive list.
     */
    if (_timer_active) {
        t_prev_ptr = &_timer_active;
        while (*t_prev_ptr) {
            t_prev_ptr = &(*t_prev_ptr)->next;
        }
        *t_prev_ptr = _timer_inactive;
        _timer_inactive = _timer_active;
        _timer_active = NULL;
    }
    /*  De-allocate timers.
     */
    while (_timer_inactive) {
        t = _timer_inactive;
        _timer_inactive = _timer_inactive->next;
        free (t);
    }
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock timer mutex");
    }
    return;
}


long
timer_set_absolute (callback_f cb, void *arg, const struct timespec *tsp)
{
    timer_p  t;
    timer_p *t_prev_ptr;
    int      do_signal = 0;

    if (!cb || !tsp) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock timer mutex");
    }
    if (!(t = _timer_alloc ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate timer");
    }
    /*  Initialize the timer.
     */
    _timer_id++;
    if (_timer_id <= 0) {
        _timer_id = 1;
    }
    t->id = _timer_id;
    t->f = cb;
    t->arg = arg;
    t->ts = *tsp;

    /*  Insert the timer into the active list.
     */
    t_prev_ptr = &_timer_active;
    while (*t_prev_ptr && clock_is_timespec_le (&(*t_prev_ptr)->ts, &t->ts)) {
        t_prev_ptr = &(*t_prev_ptr)->next;
    }
    t->next = *t_prev_ptr;
    *t_prev_ptr = t;

    /*  Only signal the timer thread if the active timer has changed.
     *  Set a flag here so the signal can be done outside the monitor lock.
     */
    if (t_prev_ptr == &_timer_active) {
        do_signal = 1;
    }
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock timer mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&_timer_cond)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to signal timer condition");
        }
    }
    assert (t->id > 0);
    return (t->id);
}


long
timer_set_relative (callback_f cb, void *arg, long msec)
{
    struct timespec ts;
    int rv;

    /*  Convert the relative time offset into an absolute timespec from now.
     */
    rv = clock_get_timespec (&ts, msec);
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to query current time");
    }
    return (timer_set_absolute (cb, arg, &ts));
}


int
timer_cancel (long id)
{
    timer_p *t_prev_ptr;
    timer_p  t = NULL;
    int      do_signal = 0;

    if (id <= 0) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock timer mutex");
    }
    /*  Locate the active timer specified by [id].
     */
    t_prev_ptr = &_timer_active;
    while (*t_prev_ptr && (id != (*t_prev_ptr)->id)) {
        t_prev_ptr = &(*t_prev_ptr)->next;
    }
    /*  Remove the located timer from the active list.
     */
    if (*t_prev_ptr) {
        t = *t_prev_ptr;
        *t_prev_ptr = t->next;
        t->next = _timer_inactive;
        _timer_inactive = t;
        /*
         *  Only signal the timer thread if the active timer was canceled.
         *  Set a flag here so the signal can be done outside the monitor lock.
         */
        if (t_prev_ptr == &_timer_active) {
            do_signal = 1;
        }
    }
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock timer mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&_timer_cond)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to signal timer condition");
        }
    }
    return (t ? 1 : 0);
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void *
_timer_thread (void *arg)
{
/*  The timer thread.  It waits until the next active timer expires,
 *    at which point it invokes the timer's callback function.
 */
    sigset_t         sigset;
    int              cancel_state;
    struct timespec  ts_now;
    timer_p         *t_prev_ptr;
    timer_p          timer_expired;
    int              rv;

    if (sigfillset (&sigset)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to init timer sigset");
    }
    if (pthread_sigmask (SIG_SETMASK, &sigset, NULL) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to set timer sigset");
    }
    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock timer mutex");
    }
    pthread_cleanup_push (_timer_thread_cleanup, NULL);

    for (;;) {
        /*
         *  Wait until a timer has been added to the active list.
         */
        while (!_timer_active) {
            /*
             *  Cancellation point.
             */
            if ((errno = pthread_cond_wait (&_timer_cond, &_timer_mutex)) != 0)
            {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to wait on timer condition");
            }
        }
        /*  Disable the thread's cancellation state in case any
         *    callback functions contain cancellation points.
         */
        errno = pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &cancel_state);
        if (errno != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to disable timer thread cancellation");
        }
        rv = clock_get_timespec (&ts_now, 0);
        if (rv < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to query current time");
        }
        /*  Select expired timers.
         */
        t_prev_ptr = &_timer_active;
        while (*t_prev_ptr
                && clock_is_timespec_le (&(*t_prev_ptr)->ts, &ts_now)) {
            t_prev_ptr = &(*t_prev_ptr)->next;
        }
        if (t_prev_ptr != &_timer_active) {
            /*
             *  Move expired timers from the active list onto an expired list.
             *  All expired timers are dispatched before the active list is
             *    rescanned.  This protects against an erroneous ts_now set in
             *    the future from causing recurring timers to be continually
             *    dispatched since ts_now will be requeried once the expired
             *    list is processed.  (Issue 15)
             */
            timer_expired = _timer_active;
            _timer_active = *t_prev_ptr;
            *t_prev_ptr = NULL;
            /*
             *  Unlock the mutex while dispatching callback functions in case
             *    any need to set/cancel timers.
             */
            if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to unlock timer mutex");
            }
            /*  Dispatch expired timers.
             */
            t_prev_ptr = &timer_expired;
            while (*t_prev_ptr) {
                (*t_prev_ptr)->f ((*t_prev_ptr)->arg);
                t_prev_ptr = &(*t_prev_ptr)->next;
            }
            if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to lock timer mutex");
            }
            /*  Move the expired timers onto the inactive list.
             *  At the end of the previous while-loop, t_prev_ptr is the
             *    address of the terminating NULL of the timer_expired list.
             */
            *t_prev_ptr = _timer_inactive;
            _timer_inactive = timer_expired;
        }
        /*  Enable the thread's cancellation state.
         *  Since enabling cancellation is not a cancellation point,
         *    a pending cancel request must be tested for.  But a
         *    pthread_testcancel() is not needed here.  If active timers
         *    are present, the pthread_cond_timedwait() at the bottom of
         *    the for-loop will serve as the cancellation point; otherwise,
         *    the pthread_cond_wait() at the top of the for-loop will.
         */
        errno = pthread_setcancelstate (cancel_state, &cancel_state);
        if (errno != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to enable timer thread cancellation");
        }
        /*  Wait until the next active timer is set to expire,
         *    or until the active timer changes.
         */
        while (_timer_active) {
            /*
             *  Cancellation point.
             */
            errno = pthread_cond_timedwait (
                    &_timer_cond, &_timer_mutex, &(_timer_active->ts));

            if (errno == EINTR) {
                continue;
            }
            if ((errno == ETIMEDOUT) || (errno == 0)) {
                break;
            }
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to wait on timer condition");
        }
    }
    assert (1);                         /* not reached */
    pthread_cleanup_pop (1);
    return (NULL);
}


static void
_timer_thread_cleanup (void *arg)
{
/*  The cleanup routine for the timer thread.
 *    It ensures the mutex is released when the thread is canceled.
 */
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock timer mutex");
    }
    return;
}


static timer_p
_timer_alloc (void)
{
/*  Returns a new timer, or NULL on memory allocation failure.
 *  The mutex must be locked before calling this routine.
 */
    timer_p t;

    assert (lsd_mutex_is_locked (&_timer_mutex));

    if (_timer_inactive) {
        t = _timer_inactive;
        _timer_inactive = _timer_inactive->next;
        t->next = NULL;
    }
    else {
        t = malloc (sizeof (struct timer));
    }
    return (t);
}
