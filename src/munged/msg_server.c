/*****************************************************************************
 *  $Id: msg_server.c,v 1.3 2003/04/23 18:22:35 dun Exp $
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
#include <string.h>
#include "dprintf.h"
#include "dec_v1.h"
#include "enc_v1.h"
#include "log.h"
#include "munge_defs.h"
#include "munge_msg.h"
#include "str.h"


/*****************************************************************************
 *  Static Prototypes
 *****************************************************************************/

static int err_v1_process_msg (munge_msg_t m);


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

void
munge_msg_server_thread (munge_msg_t m)
{
/*  This thread is responsible for destroying msg [m] via _munge_msg_destroy().
 */
    munge_err_t  e;

    assert (m != NULL);

    if ((e = _munge_msg_recv (m)) != EMUNGE_SUCCESS) {
        if (m->errstr != NULL)
            log_msg (LOG_NOTICE, "%s", m->errstr);
    }
    else if (m->head.version > MUNGE_MSG_VERSION) {
        _munge_msg_set_err (m, EMUNGE_SNAFU,
            strdupf ("Invalid message version %d", m->head.version));
    }
    else {
        switch (m->head.type) {
            case MUNGE_MSG_ENC_REQ:
                enc_v1_process_msg (m);
                break;
            case MUNGE_MSG_DEC_REQ:
                dec_v1_process_msg (m);
                break;
            default:
                _munge_msg_set_err (m, EMUNGE_SNAFU,
                    strdupf ("Invalid message type %d", m->head.type));
                break;
        }
    }
    if (m->status != EMUNGE_SUCCESS) {
        err_v1_process_msg (m);
    }
    _munge_msg_destroy (m);
    return;
}


/*****************************************************************************
 *  Static Functions
 *****************************************************************************/

static int
err_v1_process_msg (munge_msg_t m)
{
/*  Returns a error message to the client.
 *  Outputs for an error message are as follows:
 *    errnum, data_len, data
 *  The NUL-terminated error string is placed in the 'data' field.
 */
    struct munge_msg_v1 *m1;            /* munge msg (v1 format)             */
    char                *p;

    assert (m != NULL);
    assert (m->status != EMUNGE_SUCCESS);

    m1 = m->pbody;

    m->head.magic = MUNGE_MSG_MAGIC;
    m->head.version = MUNGE_MSG_VERSION;
    m->head.type = MUNGE_MSG_ERROR;
    m->head.length = 0;

    p = (m->errstr != NULL) ? m->errstr : munge_strerror (m->status);
    m1->errnum = m->status;
    m1->data_len = strlen (p) + 1;
    m1->data = p;

    log_msg (LOG_INFO, "%s", p);
    _munge_msg_send (m);
    return (0);
}
