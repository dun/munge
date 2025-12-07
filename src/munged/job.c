/*****************************************************************************
 *  Copyright (C) 2007-2025 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <https://github.com/dun/munge>.
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
 *  <https://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <arpa/inet.h>                  /* inet_ntop() */
#include <assert.h>
#include <errno.h>
#include <munge.h>
#include <netinet/in.h>                 /* INET_ADDRSTRLEN */
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "conf.h"
#include "dec.h"
#include "enc.h"
#include "fd.h"
#include "job.h"
#include "log.h"
#include "m_msg.h"
#include "munge_defs.h"
#include "str.h"
#include "work.h"


/*****************************************************************************
 *  Extern Variables
 *****************************************************************************/

extern volatile sig_atomic_t got_reconfig;      /* defined in munged.c       */
extern volatile sig_atomic_t got_terminate;     /* defined in munged.c       */


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Accept client connections and queue requests to the workers.
 *  Handle SIGHUP (for configuration reloads) and exit on SIGINT/SIGTERM.
 */
void
job_accept (conf_t conf, work_p workers)
{
    m_msg_t m;
    int sd;
    int curr_errno;
    time_t curr_time;
    int last_log_errno = 0;
    time_t last_log_time = 0;
    const int log_limit_secs = 300;

    assert (conf != NULL);
    assert (conf->ld >= 0);
    assert (workers != NULL);

    while (!got_terminate) {
        if (got_reconfig) {
            log_msg (LOG_NOTICE, "Processing signal %d (%s)",
                    got_reconfig, strsignal (got_reconfig));
            got_reconfig = 0;
            gids_update (conf->gids);
        }
        sd = accept (conf->ld, NULL, NULL);
        if (sd < 0) {
            /*  Handle accept() failure.
             *  Transient errors are ignored and retried.
             *  Resource exhaustion errors trigger throttled logging and
             *    backlog processing to prevent log flooding while allowing
             *    the system to recover.
             *  ENOMEM here often indicates socket buffer exhaustion rather
             *    than general memory depletion, and processing the backlog
             *    may free socket resources.  This differs from its typical
             *    handling where memory exhaustion is treated as fatal.
             *  All other errors are considered fatal.
             */
            switch (errno) {
                case ECONNABORTED:
                case EINTR:
                    continue;
                case EMFILE:
                case ENFILE:
                case ENOBUFS:
                case ENOMEM:
                    /*  Preserve errno before calling time().
                     */
                    curr_errno = errno;
                    curr_time = time (NULL);
                    if (curr_time == (time_t) -1) {
                        log_errno (EMUNGE_SNAFU, LOG_ERR,
                                "Failed to query current time");
                    }
                    /*  Log if sufficient time has elapsed since last log, or
                     *    if errno has changed (different resource exhausted).
                     */
                    if ((curr_time - last_log_time > log_limit_secs) ||
                            (curr_errno != last_log_errno)) {
                        log_msg (LOG_WARNING,
                                "Failed to accept connection: %s",
                                strerror (curr_errno));
                        last_log_errno = curr_errno;
                        last_log_time = curr_time;
                    }
                    /*  Process backlog before accepting new connections.
                    */
                    work_wait (workers);
                    continue;
                default:
                    log_errno (EMUNGE_SNAFU, LOG_ERR,
                            "Failed to accept connection");
                    break;
            }
        }
        /*  Handle successful accept().
         *  Set the client socket non-blocking to guard against spurious
         *    readiness notifications that could cause functions to block.
         *  Create, bind, and queue message to the workers for processing.
         *
         *  Note: Throttle state is not reset here to avoid excessive logging
         *    during oscillating resource exhaustion.  The errno change
         *    detection handles transitions between different resource types.
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
        else if (work_queue (workers, m) < 0) {
            m_msg_destroy (m);
            log_msg (LOG_WARNING, "Failed to queue client request");
        }
    }
    log_msg (LOG_NOTICE, "Exiting on signal %d (%s)",
            got_terminate, strsignal (got_terminate));
}


/*  Receive and process a client message request, logging any errors.
 */
void
job_exec (m_msg_t m)
{
    munge_err_t e;
    const char *err_msg;
    const char *ip_addr_str;

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
    /*  Some errors indicate the credential was successfully decoded but
     *    rejected for policy reasons.  In these cases, the origin IP address
     *    is available from the decoded credential and logged to identify the
     *    source.  These use LOG_DEBUG since clients can ignore these errors,
     *    avoiding log noise for operations that succeed from the client's
     *    perspective.  This is a temporary mitigation until this error
     *    handling can be moved into munged itself.  Other errors are logged
     *    at the typical LOG_INFO.
     */
    if (m->error_num != EMUNGE_SUCCESS) {
        err_msg = (m->error_str != NULL)
                ? m->error_str
                : munge_strerror (m->error_num);
        ip_addr_str = NULL;
        switch (m->error_num) {
            case EMUNGE_CRED_EXPIRED:
            case EMUNGE_CRED_REWOUND:
            case EMUNGE_CRED_REPLAYED:
                if (m->addr_len == 4) {
                    char buf[INET_ADDRSTRLEN];
                    ip_addr_str = inet_ntop (AF_INET, &m->addr,
                            buf, sizeof buf);
                }
                if (ip_addr_str != NULL) {
                    log_msg (LOG_DEBUG, "%s from %s", err_msg, ip_addr_str);
                }
                else {
                    log_msg (LOG_DEBUG, "%s", err_msg);
                }
                break;
            default:
                log_msg (LOG_INFO, "%s", err_msg);
                break;
        }
    }
    m_msg_destroy (m);
}
