/*****************************************************************************
 *  $Id: sock.c,v 1.7 2004/06/11 20:54:32 dun Exp $
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


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <munge.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "common.h"
#include "missing.h"
#include "conf.h"
#include "munge_msg.h"
#include "msg_server.h"


/*****************************************************************************
 *  Extern Variables
 *****************************************************************************/

extern int done;                        /* defined in munged.c               */


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef void * (*thrfun_t) (void *);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

void
munge_sock_create (conf_t conf)
{
    struct sockaddr_un  addr;
    int                 sd;
    int                 n;
    mode_t              mask;

    assert (conf != NULL);

    if ((conf->socket_name == NULL) || (*conf->socket_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Munge socket has no name");
    }
    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to create socket");
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, conf->socket_name, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Exceeded maximum length of socket pathname");
    }
    mask = umask (0);                   /* ensure sock access perms of 0777 */

    if (conf->got_force) {
        unlink (conf->socket_name);     /* ignoring errors */
    }
    if (bind (sd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to bind to \"%s\"", conf->socket_name);
    }

    umask (mask);                       /* restore umask */

    if (listen (sd, MUNGE_SOCKET_BACKLOG) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to listen to \"%s\"", conf->socket_name);
    }
    conf->ld = sd;
    return;
}


void
munge_sock_destroy (conf_t conf)
{
    assert (conf != NULL);
    assert (conf->ld >= 0);
    assert (conf->socket_name != NULL);

    if (conf->socket_name) {
        if (unlink (conf->socket_name) < 0) {
            log_msg (LOG_WARNING, "Unable to unlink \"%s\": %s",
                conf->socket_name, strerror (errno));
        }
    }
    if (conf->ld >= 0) {
        if (close (conf->ld) < 0) {
            log_msg (LOG_WARNING, "Unable to close \"%s\": %s",
                conf->ld, strerror (errno));
        }
        conf->ld = -1;
    }
    return;
}


void
munge_sock_accept (conf_t conf)
{
    pthread_t tid;
    pthread_attr_t tattr;
    size_t stacksize = 65536;
    munge_msg_t m;
    int sd;

    assert (conf != NULL);
    assert (conf->ld >= 0);

    if ((errno = pthread_attr_init (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to init thread attribute");
    }
    if ((errno = pthread_attr_setdetachstate (
      &tattr, PTHREAD_CREATE_DETACHED)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to set thread detached attribute");
    }
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    if ((errno = pthread_attr_setstacksize (&tattr, stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to set thread stacksize");
    }
    if ((errno = pthread_attr_getstacksize (&tattr, &stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to get thread stacksize");
    }
    log_msg (LOG_DEBUG, "Set thread stacksize to %d", (int) stacksize);
#else  /* !_POSIX_THREAD_ATTR_STACKSIZE */
    log_msg (LOG_DEBUG, "Setting thread stacksize not supported");
#endif /* !_POSIX_THREAD_ATTR_STACKSIZE */

    while (!done) {
        if ((sd = accept (conf->ld, NULL, NULL)) < 0) {
            if (errno == EINTR)
                continue;
            else if (errno == ECONNABORTED)
                continue;
            else
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to accept connection");
        }
        /*  XXX: The munge_msg_server_thread() is responsible for
         *       destroying this msg via _munge_msg_destroy().
         */
        if (_munge_msg_create (&m, sd) != EMUNGE_SUCCESS) {
            close (sd);
            log_msg (LOG_WARNING, "Unable to create message struct");
        }
        else if ((errno = pthread_create (&tid, &tattr,
          (thrfun_t) munge_msg_server_thread, m)) != 0) {
            _munge_msg_destroy (m);
            log_msg (LOG_WARNING,
                "Unable to create thread: %s", strerror (errno));
        }
    }
    if ((errno = pthread_attr_destroy (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to destroy thread attribute");
    }
    return;
}
