/*****************************************************************************
 *  $Id: munged.c,v 1.1 2003/04/08 18:16:16 dun Exp $
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

#include <munge.h>
#include <stdlib.h>
#include "common.h"
#include "conf.h"
#include "crypto_thread.h"
#include "posignal.h"
#include "random.h"
#include "sock.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void exit_handler (int signum);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

conf_t  conf = NULL;                    /* FIXME: doc me                     */
int     done = 0;                       /* FIXME: doc me                     */


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);

    if (posignal (SIGHUP, SIG_IGN) == SIG_ERR)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGHUP);
    if (posignal (SIGINT, exit_handler) == SIG_ERR)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to handle signal=%d", SIGINT);
    if (posignal (SIGTERM, exit_handler) == SIG_ERR)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to handle signal=%d", SIGTERM);
    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGPIPE);

    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    // FIXME: parse config file

    random_init (conf->seed_name);
    crypto_thread_init ();
    create_subkeys (conf);

    // FIXME: reset logging
    // FIXME: daemonize?

    munge_sock_create (conf);
    munge_sock_accept (conf);
    munge_sock_destroy (conf);

    crypto_thread_fini ();
    random_fini (conf->seed_name);
    destroy_conf (conf);

    exit (EMUNGE_SUCCESS);
}


static void
exit_handler (int signum)
{
    log_msg (LOG_NOTICE, "Exiting on signal=%d", signum);
    done = 1;
    return;
}
