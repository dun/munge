/*****************************************************************************
 *  $Id: msg_server.c,v 1.1 2003/04/08 18:16:16 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
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
#include "dprintf.h"
#include "enc_v1.h"
#include "log.h"
#include "munge_defs.h"
#include "munge_msg.h"


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

void
munge_msg_server_thread (munge_msg_t m)
{
/*  This thread is responsible for destroying msg [m] via _munge_msg_destroy().
 */
    munge_err_t e;

    assert (m != NULL);

    e = _munge_msg_recv (m);
    if (e != EMUNGE_SUCCESS) {
        if (m->error)
            log_msg (LOG_NOTICE, "%s", m->error);
        goto end;
    }
    if (m->head.version > MUNGE_MSG_VERSION) {
        log_msg (LOG_NOTICE, "Received invalid message version %d",
            m->head.version);
        // FIXME: send err rsp
        goto end;
    }
    switch (m->head.type) {
        case MUNGE_MSG_ENC_REQ:
            if (enc_v1_process (m) < 0)
                goto end;
            break;
        case MUNGE_MSG_DEC_REQ:
//          dec_v1_process (m);
            break;
        default:
            log_msg (LOG_NOTICE, "Received invalid message type %d",
                m->head.type);
            // FIXME: send err rsp
            goto end;
    }
    e = _munge_msg_send (m);

end:
    // FIXME: if (m->error) send_err()?
    // FIXME: memory corruption seems to be occurring in _munge_msg_destroy().
    _munge_msg_destroy (m);
    return;
}
