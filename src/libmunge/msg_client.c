/*****************************************************************************
 *  $Id: msg_client.c,v 1.7 2004/01/30 23:16:33 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>                  /* include before socket.h for bsd */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <munge.h>
#include "msg_client.h"
#include "munge_defs.h"
#include "munge_msg.h"
#include "str.h"
#include "strlcpy.h"


munge_err_t
_munge_msg_client_connect (munge_msg_t m, char *path)
{
    struct stat         st;
    struct sockaddr_un  addr;
    int                 sd;
    int                 n;
    int                 i;
    int                 delay;

    assert (m != NULL);
    assert (m->sd < 0);

    if ((path == NULL) || (*path == '\0')) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdup ("Munge socket has no name"));
        return (EMUNGE_SOCKET);
    }
    if (stat (path, &st) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to access \"%s\": %s", path, strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    if (!S_ISSOCK (st.st_mode)) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Invalid file type for socket \"%s\"", path));
        return (EMUNGE_SOCKET);
    }
    if ((sd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to create socket: %s", strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    memset (&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    n = strlcpy (addr.sun_path, path, sizeof (addr.sun_path));
    if (n >= sizeof (addr.sun_path)) {
        close (sd);
        _munge_msg_set_err (m, EMUNGE_OVERFLOW,
            strdup ("Exceeded maximum length of socket pathname"));
        return (EMUNGE_OVERFLOW);
    }
    i = 1;
    delay = 1;
    for (;;) {
        /*
         * If a call to connect() for a Unix domain stream socket finds that
         *   the listening socket's queue is full, ECONNREFUSED is returned
         *   immediately.  (cf, Stevens UNPv1, s14.4, p378)
         * If ECONNREFUSED, try again up to MUNGE_SOCKET_CONNECT_RETRIES.
         */
        n = connect (sd, (struct sockaddr *) &addr, sizeof (addr));
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        if (errno != ECONNREFUSED)
            break;
        if (i >= MUNGE_SOCKET_CONNECT_RETRIES)
            break;
        sleep (delay);
        delay++;
        i++;
    }
    if (n < 0) {
        close (sd);
        _munge_msg_set_err (m, EMUNGE_SOCKET,
            strdupf ("Unable to connect to \"%s\": %s", path,
            strerror (errno)));
        return (EMUNGE_SOCKET);
    }
    m->sd = sd;
    return (EMUNGE_SUCCESS);
}


munge_err_t
_munge_msg_client_disconnect (munge_msg_t m)
{
    munge_err_t e = EMUNGE_SUCCESS;

    assert (m != NULL);
    assert (m->sd >= 0);

    if (m->sd >= 0) {
        if (close (m->sd) < 0) {
            _munge_msg_set_err (m, EMUNGE_SOCKET,
                strdupf ("Unable to close socket: %s", strerror (errno)));
            e = EMUNGE_SOCKET;
        }
        m->sd = -1;
    }
    return (e);
}
