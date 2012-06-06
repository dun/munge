/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2012 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://munge.googlecode.com/>.
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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>
#include "log.h"
#include "thread.h"
#include "timer.h"


/*****************************************************************************
 *  Private Data Types
 *****************************************************************************/

struct timer {
    long                id;             /* timer ID                          */
    struct timespec     ts;             /* time at which timer expires       */
    callback_f          f;              /* callback function                 */
    void               *arg;            /* callback function arg             */
    struct timer       *next;           /* next timer in list                */
};

typedef struct timer * timer_p;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void * _timer_thread (void *arg);

static void _timer_thread_cleanup (void *arg);

static timer_p _timer_alloc (void);

static void _timer_get_timespec (struct timespec *tsp);

static int _timer_is_timespec_ge (
        struct timespec *tsp0, struct timespec *tsp1);


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

static pthread_t       _timer_tid = 0;
static pthread_cond_t  _timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t _timer_mutex = PTHREAD_MUTEX_INITIALIZER;

static long            _timer_id = 0;
static timer_p         _timer_active = NULL;
static timer_p         _timer_inactive = NULL;

/*  The _timer_id is the ID of the last timer that was set.
 */
/*  The _timer_active list is sorted in order of increasing timespecs.
 *    The head of the list is the next timer to expire.
 */


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
timer_init (void)
{
    pthread_attr_t tattr;
    size_t stacksize = 256 * 1024;

    if (_timer_tid != 0) {
        return;
    }
    if ((errno = pthread_attr_init (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to init timer thread attribute");
    }
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    if ((errno = pthread_attr_setstacksize (&tattr, stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to set timer thread stacksize");
    }
    if ((errno = pthread_attr_getstacksize (&tattr, &stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to get timer thread stacksize");
    }
    log_msg (LOG_DEBUG, "Set timer thread stacksize to %d", (int) stacksize);
#endif /* _POSIX_THREAD_ATTR_STACKSIZE */

    if ((errno = pthread_create (&_timer_tid, &tattr, _timer_thread, NULL))
            !=0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to create timer thread");
    }
    if ((errno = pthread_attr_destroy (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to destroy timer thread attribute");
    }
    return;
}


void
timer_fini (void)
{
    void     *result;
    timer_p  *t_ptr;
    timer_p   t;

    if (_timer_tid == 0) {
        return;
    }
    if ((errno = pthread_cancel (_timer_tid)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to cancel timer thread");
    }
    if ((errno = pthread_join (_timer_tid, &result)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to join timer thread");
    }
    if (result != PTHREAD_CANCELED) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Timer thread was not canceled");
    }
    _timer_tid = 0;

    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    /*  Cancel pending timers.
     */
    t_ptr = &_timer_active;
    while (*t_ptr) {
        t_ptr = &(*t_ptr)->next;
    }
    *t_ptr = _timer_inactive;
    _timer_inactive = _timer_active;
    _timer_active = NULL;
    /*
     *  De-allocate timers.
     */
    while (_timer_inactive) {
        t = _timer_inactive;
        _timer_inactive = _timer_inactive->next;
        free (t);
    }
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    return;
}


long
timer_set_absolute (callback_f cb, void *arg, const struct timespec *tsp)
{
    timer_p      t;
    timer_p      t_curr;
    timer_p     *t_prev_ptr;
    int          do_signal = 0;

    if (!cb || !tsp) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    if (!(t = _timer_alloc ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to allocate timer");
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
    /*
     *  Insert the timer into the active list.
     */
    t_prev_ptr = &_timer_active;
    t_curr = *t_prev_ptr;
    while (t_curr && _timer_is_timespec_ge (&t->ts, &t_curr->ts)) {
        t_prev_ptr = &t_curr->next;
        t_curr = *t_prev_ptr;
    }
    *t_prev_ptr = t;
    t->next = t_curr;
    /*
     *  Only signal the timer thread if the active timer has changed.
     *  Set a flag here so the signal can be done outside the monitor lock.
     */
    if (t_prev_ptr == &_timer_active) {
        do_signal = 1;
    }
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&_timer_cond)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to signal timer condition");
        }
    }
    assert (t->id > 0);
    return (t->id);
}


long
timer_set_relative (callback_f cb, void *arg, int ms)
{
    struct timespec ts;

    /*  Convert the relative time offset into an absolute timespec from now.
     */
    _timer_get_timespec (&ts);

    if (ms > 0) {
        ts.tv_sec += ms / 1000;
        ts.tv_nsec += (ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += ts.tv_nsec / 1000000000;
            ts.tv_nsec %= 1000000000;
        }
    }
    return (timer_set_absolute (cb, arg, &ts));
}


int
timer_cancel (long id)
{
    timer_p     t_curr;
    timer_p    *t_prev_ptr;
    int         do_signal = 0;

    if (id <= 0) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    /*  Locate the active timer specified by [id].
     */
    t_prev_ptr = &_timer_active;
    t_curr = *t_prev_ptr;
    while (t_curr && (id != t_curr->id)) {
        t_prev_ptr = &t_curr->next;
        t_curr = *t_prev_ptr;
    }
    /*  Remove the located timer from the active list.
     */
    if (t_curr != NULL) {
        *t_prev_ptr = t_curr->next;
        t_curr->next = _timer_inactive;
        _timer_inactive = t_curr;
        /*
         *  Only signal the timer thread if the active timer was canceled.
         *  Set a flag here so the signal can be done outside the monitor lock.
         */
        if (t_prev_ptr == &_timer_active) {
            do_signal = 1;
        }
    }
    if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&_timer_cond)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to signal timer condition");
        }
    }
    return (t_curr ? 1 : 0);
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
    sigset_t            sigset;
    int                 cancel_state;
    struct timespec     ts_now;
    timer_p            *tp;
    timer_p             timer_expired;

    if (sigfillset (&sigset)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to init timer sigset");
    }
    if (pthread_sigmask (SIG_SETMASK, &sigset, NULL) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set timer sigset");
    }
    if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
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
                    "Unable to wait on timer condition");
            }
        }
        /*  Disable the thread's cancellation state in case any
         *    callback functions contain cancellation points.
         */
        if ((errno = pthread_setcancelstate
          (PTHREAD_CANCEL_DISABLE, &cancel_state)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to disable timer thread cancellation");
        }
        /*  Select expired timers.
         *  Expired timers are moved from the active list onto an expired list.
         *    All expired timers are then dispatched before the active list is
         *    rescanned.  This protects against an erroneous ts_now set in the
         *    future from causing recurring timers to be continually dispatched
         *    since ts_now will be requeried once the expired list is processed
         *    (cf, <http://code.google.com/p/munge/issues/detail?id=15>).
         */
        _timer_get_timespec (&ts_now);
        tp = &_timer_active;
        while (*tp && _timer_is_timespec_ge (&ts_now, &(*tp)->ts)) {
            tp = &(*tp)->next;
        }
        if (tp != &_timer_active) {
            timer_expired = _timer_active;
            _timer_active = *tp;
            *tp = NULL;
        }
        else {
            timer_expired = NULL;
        }
        /*  Unlock the mutex while dispatching callback functions in case any
         *    need to set/cancel timers.  Note that expired timers have been
         *    removed from the active list while they are being dispatched.
         */
        if ((errno = pthread_mutex_unlock (&_timer_mutex)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to unlock timer mutex");
        }
        /*  Dispatch expired timers.
         */
        tp = &timer_expired;
        while (*tp) {
            (*tp)->f ((*tp)->arg);
            tp = &(*tp)->next;
        }
        if ((errno = pthread_mutex_lock (&_timer_mutex)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to lock timer mutex");
        }
        if (timer_expired) {
            *tp = _timer_inactive;
            _timer_inactive = timer_expired;
        }
        /*  Enable the thread's cancellation state.
         *    Since enabling cancellation is not a cancellation point,
         *    a pending cancel request must be tested for.  But a
         *    pthread_testcancel() is not needed here.  If active timers
         *    are present, the pthread_cond_timedwait() at the bottom of
         *    the for-loop will serve as the cancellation point; otherwise,
         *    the pthread_cond_wait() at the top of the for-loop will.
         */
        if ((errno = pthread_setcancelstate
          (cancel_state, &cancel_state)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to enable timer thread cancellation");
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
            if (errno == EINTR)
                continue;
            if ((errno == ETIMEDOUT) || (errno == 0))
                break;
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to wait on timer condition");
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
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    return;
}


static timer_p
_timer_alloc (void)
{
/*  Returns a new timer, or NULL if memory allocation fails.
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


static void
_timer_get_timespec (struct timespec *tsp)
{
/*  Sets the timespec [tsp] to the current time.
 */
    struct timeval tv;

    assert (tsp != NULL);

    /*  In theory, gettimeofday() gives microsecond precision.
     *    Your reality may be different.
     */
    if (gettimeofday (&tv, NULL) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to get time of day");
    }
    tsp->tv_sec = tv.tv_sec;
    tsp->tv_nsec = tv.tv_usec * 1000;
    assert (tsp->tv_nsec < 1000000000);
    return;
}


static int
_timer_is_timespec_ge (struct timespec *tsp0, struct timespec *tsp1)
{
/*  Returns non-zero if the time specified by [tsp0] is
 *    greater than or equal to the time specified by [tsp1].
 */
    assert (tsp0 != NULL);
    assert (tsp1 != NULL);
    assert (tsp0->tv_nsec < 1000000000);
    assert (tsp1->tv_nsec < 1000000000);

    if (tsp0->tv_sec == tsp1->tv_sec)
        return (tsp0->tv_nsec >= tsp1->tv_nsec);
    else
        return (tsp0->tv_sec >= tsp1->tv_sec);
}
