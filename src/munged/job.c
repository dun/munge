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


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <arpa/inet.h>                  /* for inet_ntop() */
#include <assert.h>
#include <errno.h>
#include <munge.h>
#include <netinet/in.h>                 /* for INET_ADDRSTRLEN */
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "conf.h"
#include "dec.h"
#include "enc.h"
#include "fd.h"
#include "log.h"
#include "m_msg.h"
#include "munge_defs.h"
#include "str.h"
#include "work.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/
#define LOG_LIMIT_SECS  60


/*****************************************************************************
 *  Extern Variables
 *****************************************************************************/

extern volatile sig_atomic_t got_reconfig;      /* defined in munged.c       */
extern volatile sig_atomic_t got_terminate;     /* defined in munged.c       */


/*****************************************************************************
 *  Private Prototypes
 *****************************************************************************/

static void _job_exec (m_msg_t m);


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

void
job_accept (conf_t conf)
{
    work_p  w;
    m_msg_t m;
    int     sd;
    int     curr_errno;
    time_t  curr_time;
    int     last_log_errno = 0;
    time_t  last_log_time = 0;

    assert (conf != NULL);
    assert (conf->ld >= 0);

    if (!(w = work_init ((work_func_t) _job_exec, conf->nthreads))) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to create %d work thread%s", conf->nthreads,
            ((conf->nthreads > 1) ? "s" : ""));
    }
    log_msg (LOG_INFO, "Created %d work thread%s", conf->nthreads,
            ((conf->nthreads > 1) ? "s" : ""));

    while (!got_terminate) {
        if (got_reconfig) {
            log_msg (LOG_NOTICE, "Processing signal %d (%s)",
                    got_reconfig, strsignal (got_reconfig));
            got_reconfig = 0;
            gids_update (conf->gids);
        }
        sd = accept (conf->ld, NULL, NULL);
        if (sd < 0) {
            switch (errno) {
                case ECONNABORTED:
                case EINTR:
                    continue;
                case EMFILE:
                case ENFILE:
                case ENOBUFS:
                case ENOMEM:
                    curr_errno = errno; /* save errno before calling time() */
                    curr_time = time (NULL);
                    if (curr_time == (time_t) -1) {
                        log_errno (EMUNGE_SNAFU, LOG_ERR,
                                "Failed to query current time");
                    }
                    if ((curr_time > last_log_time + LOG_LIMIT_SECS) ||
                            (curr_errno != last_log_errno)) {
                        log_msg (LOG_INFO, "Failed to accept connection: %s",
                                strerror (curr_errno));
                        last_log_errno = curr_errno;
                        last_log_time = curr_time;
                    }
                    /*  Process backlog before accepting new connections.
                    */
                    work_wait (w);
                    continue;
                default:
                    log_errno (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to accept connection");
                    break;
            }
        }
        /*  With fd_timed_read_n(), a poll() is performed before any read()
         *    in order to provide timeouts and ensure the read() won't block.
         *    As such, it shouldn't be necessary to set the client socket as
         *    non-blocking.  However according to the Linux poll(2) and
         *    select(2) manpages, spurious readiness notifications can occur.
         *    poll()/select() may report a socket as ready for reading while
         *    the subsequent read() blocks.  This could happen when data has
         *    arrived, but upon examination is discarded due to an invalid
         *    checksum.  To protect against this, the client socket is set
         *    non-blocking and EAGAIN is handled appropriately.
         */
        if (fd_set_nonblocking (sd) < 0) {
            close (sd);
            log_msg (LOG_WARNING,
                "Failed to set nonblocking client socket: %s",
                strerror (errno));
        }
        else if (m_msg_create (&m) != EMUNGE_SUCCESS) {
            close (sd);
            log_msg (LOG_WARNING, "Failed to create client request");
        }
        else if (m_msg_bind (m, sd) != EMUNGE_SUCCESS) {
            m_msg_destroy (m);
            log_msg (LOG_WARNING, "Failed to bind socket for client request");
        }
        else if (work_queue (w, m) < 0) {
            m_msg_destroy (m);
            log_msg (LOG_WARNING, "Failed to queue client request");
        }
    }
    log_msg (LOG_NOTICE, "Exiting on signal %d (%s)",
            got_terminate, strsignal (got_terminate));
    work_fini (w, 1);
    return;
}


/*****************************************************************************
 *  Private Functions
 *****************************************************************************/

static void
_job_exec (m_msg_t m)
{
/*  Receives and responds to the message request [m].
 */
    munge_err_t  e;
    const char  *p;

    assert (m != NULL);

    e = m_msg_recv (m, MUNGE_MSG_UNDEF, MUNGE_MAXIMUM_REQ_LEN);
    if (e == EMUNGE_SUCCESS) {
        switch (m->type) {
            case MUNGE_MSG_ENC_REQ:
                enc_process_msg (m);
                break;
            case MUNGE_MSG_DEC_REQ:
                dec_process_msg (m);
                break;
            default:
                m_msg_set_err (m, EMUNGE_SNAFU,
                    strdupf ("Invalid message type %d", m->type));
                break;
        }
    }
    /*  For certain MUNGE "cred" errors, the credential has been successfully
     *    decoded but is deemed invalid for other reasons.  In these cases,
     *    the origin IP address is added to the logged error message to aid
     *    in troubleshooting.
     */
    if (m->error_num != EMUNGE_SUCCESS) {
        p = (m->error_str != NULL)
            ? m->error_str
            : munge_strerror (m->error_num);
        switch (m->error_num) {
            case EMUNGE_CRED_EXPIRED:
            case EMUNGE_CRED_REWOUND:
            case EMUNGE_CRED_REPLAYED:
                if (m->addr_len == 4) {
                    char ip_addr_buf [INET_ADDRSTRLEN];
                    if (inet_ntop (AF_INET, &m->addr, ip_addr_buf,
                                   sizeof (ip_addr_buf)) != NULL) {
                        log_msg (LOG_INFO, "%s from %s", p, ip_addr_buf);
                        break;
                    }
                }
                /* fall-through */
            default:
                log_msg (LOG_INFO, "%s", p);
                break;
        }
    }
    m_msg_destroy (m);
    return;
}
