/*****************************************************************************
 *  $Id: work.c,v 1.3 2004/09/17 20:23:35 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2004 The Regents of the University of California.
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
 *****************************************************************************
 *  Refer to "work.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <munge.h>
#include "log.h"
#include "work.h"


/*****************************************************************************
 *  Private Data Types
 *****************************************************************************/

typedef struct work_arg {
    struct work_arg    *next;           /* next work element in queue        */
    void               *arg;            /* arg describing work to be done    */
} work_arg_t, *work_arg_p;

typedef struct work {
    pthread_mutex_t     lock;           /* mutex for accessing struct        */
    pthread_cond_t      received_work;  /* cond for when new work is recv'd  */
    pthread_cond_t      finished_work;  /* cond for when all work is done    */
    pthread_t          *workers;        /* ptr to array of worker thread IDs */
    work_func_t         work_func;      /* function to perform work in queue */
    work_arg_p          work_head;      /* head of the work queue            */
    work_arg_p          work_tail;      /* tail of the work queue            */
    int                 n_workers;      /* number of worker threads (total)  */
    int                 n_working;      /* number of worker threads working  */
    int                 got_fini;       /* true prevents new work after fini */
} work_t;


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void * _work_exec (void *arg);
static void   _work_exec_cleanup (void *arg);
static void * _work_enqueue (work_p wp, void *work);
static void * _work_dequeue (work_p wp);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

work_p
work_init (work_func_t f, int n_threads)
{
    work_p wp;
    pthread_attr_t tattr;
    size_t stacksize = 256 * 1024;
    int i;

    /*  Check args.
     */
    if (f == NULL) {
        errno = EINVAL;
        return (NULL);
    }
    if (n_threads <= 0) {
        errno = EINVAL;
        return (NULL);
    }
    /*  Allocate memory.
     */
    if (!(wp = malloc (sizeof (work_t)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate work thread struct");
    }
    if (!(wp->workers = malloc (sizeof (*wp->workers) * n_threads))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate tid array for work thread struct");
    }
    /*  Initialize struct.
     */
    if ((errno = pthread_attr_init (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to init work thread attribute");
    }
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    if ((errno = pthread_attr_setstacksize (&tattr, stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to set work thread stacksize");
    }
    if ((errno = pthread_attr_getstacksize (&tattr, &stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to get work thread stacksize");
    }
    log_msg (LOG_DEBUG, "Set work thread stacksize to %d", (int) stacksize);
#endif /* _POSIX_THREAD_ATTR_STACKSIZE */

    if ((errno = pthread_mutex_init (&wp->lock, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to init work thread mutex");
    }
    if ((errno = pthread_cond_init (&wp->received_work, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to init work thread received-work condition");
    }
    if ((errno = pthread_cond_init (&wp->finished_work, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to init work thread finished-work condition");
    }
    wp->work_func = f;
    wp->work_head = wp->work_tail = NULL;
    wp->n_workers = n_threads;
    wp->n_working = 0;
    wp->got_fini = 0;
    /*
     *  Start worker thread(s).
     */
    for (i = 0; i < wp->n_workers; i++) {
        if ((errno = pthread_create
                    (&wp->workers[i], &tattr, _work_exec, wp)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to create worker thread #%d", i+1);
        }
    }
    /*  Cleanup.
     */
    if ((errno = pthread_attr_destroy (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to destroy work thread attribute");
    }
    return (wp);
}


void
work_fini (work_p wp, int do_wait)
{
    int i;

    if (!wp) {
        errno = EINVAL;
        return;
    }
    if ((errno = pthread_mutex_lock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to lock work thread mutex");
    }
    /*  Prevent new work from being queued.
     */
    wp->got_fini = 1;
    /*
     *  Process remaining work if requested.
     */
    if (do_wait) {
        /*
         *  Calling work_wait() won't work here since the wait wouldn't
         *    be atomic with the mutex being dropped between function calls.
         */
        while ((wp->n_working != 0) && (wp->work_head != NULL)) {
            if ((errno = pthread_cond_wait
                        (&wp->finished_work, &wp->lock)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to wait on work thread for finished work");
            }
        }
    }
    /*  Stop worker thread(s).
     *  The mutex must be unlocked in order to cancel the worker
     *    thread(s) which may be blocked on pthread_cond_wait().
     *    When a pthread_cond_wait() is canceled, the mutex is
     *    re-acquired before the cleanup handlers are invoked.
     */
    if ((errno = pthread_mutex_unlock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to unlock work thread mutex");
    }
    for (i = 0; i < wp->n_workers; i++) {
        if ((errno = pthread_cancel (wp->workers[i])) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to cancel worker thread #%d", i+1);
        }
    }
    for (i = 0; i < wp->n_workers; i++) {
        void *result;
        if ((errno = pthread_join (wp->workers[i], &result)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to join worker thread #%d", i+1);
        }
        if (result != PTHREAD_CANCELED) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Worker thread #%d was not canceled", i+1);
        }
        wp->workers[i] = 0;
    }
    /*  Reclaim allocated resources.
     */
    if ((errno = pthread_cond_destroy (&wp->finished_work)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to destroy work thread finished-work condition");
    }
    if ((errno = pthread_cond_destroy (&wp->received_work)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to destroy work thread received-work condition");
    }
    if ((errno = pthread_mutex_destroy (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to destroy work thread mutex");
    }
    free (wp->workers);
    free (wp);
    return;
}


int
work_queue (work_p wp, void *work)
{
    int rc;
    int do_signal = 0;

    if (!wp || !work) {
        errno = EINVAL;
        return (-1);
    }
    if ((errno = pthread_mutex_lock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to lock work thread mutex");
    }
    if (wp->got_fini) {
        errno = EPERM;
        rc = -1;
    }
    else {
        /*
         *  Awaken an idle worker if possible.
         *  Set a flag here so the signal can be done outside the monitor lock.
         */
        if ((wp->n_workers - wp->n_working) > 0) {
            do_signal = 1;
        }
        if (_work_enqueue (wp, work) != NULL) {
            rc = 0;
        }
    }
    if ((errno = pthread_mutex_unlock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to unlock work thread mutex");
    }
    if (do_signal) {
        if ((errno = pthread_cond_signal (&wp->received_work)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to signal work thread for received work");
        }
    }
    return (rc);
}


void
work_wait (work_p wp)
{
    if (!wp) {
        errno = EINVAL;
        return;
    }
    if ((errno = pthread_mutex_lock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to lock work thread mutex");
    }
    /*  Wait until all the queued work is finished.
     */
    while ((wp->n_working != 0) && (wp->work_head != NULL)) {
        if ((errno = pthread_cond_wait (&wp->finished_work, &wp->lock)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to wait on work thread for finished work");
        }
    }
    if ((errno = pthread_mutex_unlock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to unlock work thread mutex");
    }
    return;
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void *
_work_exec (void *arg)
{
/*  The worker thread.  It continually removes the next element
 *    from the work queue and processes it -- until it's canceled.
 */
    work_p wp;
    int cancel_state;
    void *work;

    assert (arg != NULL);
    wp = arg;

    if ((errno = pthread_mutex_lock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to lock work thread mutex");
    }
    pthread_cleanup_push (_work_exec_cleanup, wp);

    for (;;) {

        pthread_testcancel ();
        /*
         *  Wait for new work if none is currently queued.
         */
        while (!wp->work_head) {
            if ((errno = pthread_cond_wait
                        (&wp->received_work, &wp->lock)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to wait on work thread for received work");
            }
        }
        /*  Disable the thread's cancellation state.
         */
        if ((errno = pthread_setcancelstate
                    (PTHREAD_CANCEL_DISABLE, &cancel_state)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to disable work thread cancellation");
        }
        /*  Process the work.
         */
        work = _work_dequeue (wp);
        assert (work != NULL);

        wp->n_working++;

        if ((errno = pthread_mutex_unlock (&wp->lock)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to unlock work thread mutex");
        }
        wp->work_func (work);

        if ((errno = pthread_mutex_lock (&wp->lock)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to lock work thread mutex");
        }
        wp->n_working--;
        /*
         *  Enable the thread's cancellation state.
         *    Since enabling cancellation is not a cancellation point,
         *    a pending cancel request must be tested for.  Consequently,
         *    pthread_testcancel() is called at the top of the for-loop
         *    (in case work is queued and pthread_cond_wait() isn't invoked).
         */
        if ((errno = pthread_setcancelstate
                    (cancel_state, &cancel_state)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to enable work thread cancellation");
        }
        /*  Check to see if all the queued work is now finished.
         */
        if ((wp->n_working == 0) && (!wp->work_head)) {
            if ((errno = pthread_cond_signal (&wp->finished_work)) != 0) {
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to signal work thread for finished work");
            }
        }
    }
    assert (1);                         /* not reached */
    pthread_cleanup_pop (1);
    return (NULL);
}


static void
_work_exec_cleanup (void *arg)
{
/*  The cleanup routine for the _work_exec() thread(s).
 *    It ensures the mutex is released when the thread is canceled.
 */
    work_p wp;

    assert (arg != NULL);
    wp = arg;

    if ((errno = pthread_mutex_unlock (&wp->lock)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to unlock work thread mutex");
    }
    return;
}


static void *
_work_enqueue (work_p wp, void *work)
{
/*  Enqueue the [work] element at the tail of the [wp] work queue.
 *
 *  LOCKING PROTOCOL:
 *    This routine requires the caller to have locked the [wp]'s mutex.
 */
    work_arg_p wap;

    assert (wp != NULL);

    if (!work) {
        return (NULL);
    }
    if (!(wap = malloc (sizeof (*wap)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to enqueue work element");
    }
    wap->next = NULL;
    wap->arg = work;
    if (!wp->work_tail) {
        wp->work_tail = wp->work_head = wap;
    }
    else {
        wp->work_tail->next = wap;
        wp->work_tail = wap;
    }
    return (work);
}


static void *
_work_dequeue (work_p wp)
{
/*  Dequeue the work element at the head of the [wp] work queue.
 *
 *  LOCKING PROTOCOL:
 *    This routine requires the caller to have locked the [wp]'s mutex.
 */
    work_arg_p  wap;
    void       *work;

    assert (wp != NULL);

    wap = wp->work_head;
    if (!wap) {
        return (NULL);
    }
    wp->work_head = wap->next;
    work = wap->arg;
    free (wap);
    if (!wp->work_head) {
        wp->work_tail = NULL;
    }
    return (work);
}
