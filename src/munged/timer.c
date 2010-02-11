/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
 *  Private Constants
 *****************************************************************************/

#define TIMER_ALLOC     10


/*****************************************************************************
 *  Private Data Types
 *****************************************************************************/

struct timer {
    int                 id;             /* timer id                          */
    struct timespec     ts;             /* time at which timer expires       */
    callback_f          f;              /* callback function                 */
    void               *arg;            /* callback function arg             */
    struct timer       *next;           /* next timer in list                */
};

typedef struct timer * _timer_t;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void * timer_thread (void *arg);

static void timer_thread_cleanup (void *arg);

static _timer_t timer_alloc (void);

static void timer_get_timespec (struct timespec *tsp);

static int timer_is_timespec_ge (struct timespec *tsp0, struct timespec *tsp1);


/*****************************************************************************
 *  Private Variables
 *****************************************************************************/

static pthread_t        timer_tid = 0;
static pthread_cond_t   timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t  timer_mutex = PTHREAD_MUTEX_INITIALIZER;

static _timer_t         timer_active = NULL;
static _timer_t         timer_inactive = NULL;

/*  The timer_active list is sorted in order of increasing timespecs.
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

    if (timer_tid != 0) {
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

    if ((errno= pthread_create (&timer_tid, &tattr, timer_thread, NULL)) !=0) {
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
    _timer_t   *t_ptr;
    void       *result;

    if (timer_tid == 0) {
        return;
    }
    if ((errno = pthread_cancel (timer_tid)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to cancel timer thread");
    }
    if ((errno = pthread_join (timer_tid, &result)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to join timer thread");
    }
    if (result != PTHREAD_CANCELED) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Timer thread was not canceled");
    }
    timer_tid = 0;
    /*
     *  Cancel all pending timers.
     *  Note that this method doesn't preserve the ordering of the inactive
     *    list as if the timers had been individually dispatched, but the
     *    ordering of timers on the inactive list really doesn't matter.
     *  Ideally, memory allocated to the inactive timers would be reclaimed
     *    at this point, but that's not possible in this implementation.
     */
    if ((errno = pthread_mutex_lock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    t_ptr = &timer_active;
    while (*t_ptr)
        t_ptr = &(*t_ptr)->next;
    *t_ptr = timer_inactive;
    timer_inactive = timer_active;
    timer_active = NULL;

    if ((errno = pthread_mutex_unlock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    return;
}


int
timer_set_absolute (callback_f cb, void *arg, const struct timespec *tsp)
{
    _timer_t    t;
    _timer_t    t_curr;
    _timer_t   *t_prev_ptr;
    static int  id = 1;
    int         do_signal = 0;

    if (!cb) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    if (!(t = timer_alloc ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to allocate timer");
    }
    /*  Initialize the timer.
     */
    t->id = id++;
    if (id <= 0)
        id = 1;
    t->f = cb;
    t->arg = arg;
    t->ts = *tsp;
    /*
     *  Insert the timer into the active list.
     */
    t_prev_ptr = &timer_active;
    t_curr = *t_prev_ptr;
    while (t_curr && timer_is_timespec_ge (&t->ts, &t_curr->ts)) {
        t_prev_ptr = &t_curr->next;
        t_curr = *t_prev_ptr;
    }
    *t_prev_ptr = t;
    t->next = t_curr;
    /*
     *  Only signal the timer thread if the active timer has changed.
     *  Set a flag here so the signal can be done outside the monitor lock.
     */
    if (t_prev_ptr == &timer_active) {
        do_signal = 1;
    }
    if ((errno = pthread_mutex_unlock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&timer_cond)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to signal timer condition");
        }
    }
    assert (t->id > 0);
    return (t->id);
}


int
timer_set_relative (callback_f cb, void *arg, int ms)
{
    struct timespec     ts;

    /*  Convert the relative time offset into an absolute timespec.
     */
    timer_get_timespec (&ts);

    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000;
    assert (ts.tv_nsec < 2000000000);

    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec += ts.tv_nsec / 1000000000;
        ts.tv_nsec %= 1000000000;
    }
    return (timer_set_absolute (cb, arg, &ts));
}


int
timer_cancel (int id)
{
/*  XXX: Since timer IDs aren't guaranteed to be unique, it's possible for
 *    a given ID to be in use by more than one active timer.  In such a case,
 *    the timer with the earlier expiration time (ie, the one that will
 *    expire first) will be the one removed from the active list -- and this
 *    is probably the desired behavior.
 *  Snader suggests the use of a timer ID instead of the _timer_t's address.
 *    When a timer expires, the _timer_t is placed on the inactive list.
 *    When a new timer is set, the struct at the head of the inactive list is
 *    used.  If the app then tries to cancel the first (now expired) timer
 *    via the _timer_t's address, the second timer would be canceled instead.
 *  Thus, timer IDs appear to be the proverbial lesser of two evils here.
 */
    _timer_t    t_curr;
    _timer_t   *t_prev_ptr;
    int         do_signal = 0;

    if (id <= 0) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    /*  Locate the active timer specified by [id].
     */
    t_prev_ptr = &timer_active;
    t_curr = *t_prev_ptr;
    while (t_curr && (id != t_curr->id)) {
        t_prev_ptr = &t_curr->next;
        t_curr = *t_prev_ptr;
    }
    /*  Remove the located timer from the active list.
     */
    if (t_curr != NULL) {
        *t_prev_ptr = t_curr->next;
        t_curr->next = timer_inactive;
        timer_inactive = t_curr;
        /*
         *  Only signal the timer thread if the active timer was canceled.
         *  Set a flag here so the signal can be done outside the monitor lock.
         */
        if (t_prev_ptr == &timer_active) {
            do_signal = 1;
        }
    }
    if ((errno = pthread_mutex_unlock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&timer_cond)) != 0) {
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
timer_thread (void *arg)
{
/*  The timer thread.  It waits until the next active timer expires,
 *    at which point it invokes the timer's callback function.
 */
    sigset_t            sigset;
    int                 cancel_state;
    struct timespec     ts_now;
    _timer_t            t;

    if (sigfillset (&sigset)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to init timer sigset");
    }
    if (pthread_sigmask (SIG_SETMASK, &sigset, NULL) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set timer sigset");
    }
    if ((errno = pthread_mutex_lock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to lock timer mutex");
    }
    pthread_cleanup_push (timer_thread_cleanup, NULL);

    for (;;) {
        /*
         *  Wait until a timer has been added to the active list.
         */
        while (!timer_active) {
            /*
             *  Cancellation point.
             */
            if ((errno = pthread_cond_wait (&timer_cond, &timer_mutex)) != 0) {
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
        /*  Dispatch timer events that have expired.
         */
        timer_get_timespec (&ts_now);
        while (timer_active
               && timer_is_timespec_ge (&ts_now, &timer_active->ts)) {
            t = timer_active;
            timer_active = timer_active->next;
            /*
             *  Unlock the mutex while performing the callback function
             *    in case it wants to set/cancel another timer.
             *  Note that at this point in time, the active timer
             *    is on neither the active nor the inactive list.
             */
            if ((errno = pthread_mutex_unlock (&timer_mutex)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to unlock timer mutex");
            }
            t->f (t->arg);

            if ((errno = pthread_mutex_lock (&timer_mutex)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to lock timer mutex");
            }
            t->next = timer_inactive;
            timer_inactive = t;
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
        while (timer_active) {
            /*
             *  Cancellation point.
             */
            errno = pthread_cond_timedwait (
                &timer_cond, &timer_mutex, &(timer_active->ts));
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
timer_thread_cleanup (void *arg)
{
/*  The cleanup routine for the timer thread.
 *    It ensures the mutex is released when the thread is canceled.
 */
    if ((errno = pthread_mutex_unlock (&timer_mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to unlock timer mutex");
    }
    return;
}


static _timer_t
timer_alloc (void)
{
/*  Returns a new timer, or NULL if memory allocation fails.
 */
    _timer_t    t;
    _timer_t    t_last;

    assert (TIMER_ALLOC > 0);

    /*  The mutex must be locked before calling this routine.
     */
    assert (lsd_mutex_is_locked (&timer_mutex));

    if (!timer_inactive) {
        if (!(timer_inactive = malloc (TIMER_ALLOC * sizeof (struct timer))))
            return (NULL);
        t_last = timer_inactive + TIMER_ALLOC - 1;
        for (t = timer_inactive; t < t_last; t++)
            t->next = t + 1;
        t_last->next = NULL;
    }
    t = timer_inactive;
    timer_inactive = timer_inactive->next;
    t->next = NULL;
    return (t);
}


static void
timer_get_timespec (struct timespec *tsp)
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
timer_is_timespec_ge (struct timespec *tsp0, struct timespec *tsp1)
{
/*  Returns non-zero if the time specified by [tsp0] is
 *    greater than or equal to the time specified by [tsp1].
 *
 *  XXX: This routine is almost identical to the timercmp macro def.
 *    Comments in <sys/time.h> claim it doesn't work for >= or <=,
 *    but I can't fathom why.  To play it safe, I could implement
 *    ">=" as "!<" (eg, !timercmp(a,b,<) ), but that's an extra op.
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
