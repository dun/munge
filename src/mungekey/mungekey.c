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

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <munge.h>
#include "conf.h"
#include "crypto.h"
#include "key.h"
#include "log.h"
#include "md.h"
#include "xsignal.h"


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

static void init_logging (const char *prog);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t *confp;

    xsignal_ignore (SIGHUP);
    xsignal_ignore (SIGPIPE);
    init_logging (argv[0]);
    confp = create_conf ();
    parse_cmdline (confp, argc, argv);

    crypto_init ();
    md_init_subsystem ();
    if (confp->do_create) {
        create_key (confp);
    }
    crypto_fini ();
    destroy_conf (confp);
    exit (EXIT_SUCCESS);
}


/*  Configure logging to stderr.
 */
static void
init_logging (const char *prog)
{
    int priority = LOG_INFO;
    int options = LOG_OPT_PRIORITY;
    int rv;

    assert (prog != NULL);

#ifndef NDEBUG
    priority = LOG_DEBUG;
#endif /* !NDEBUG */
    rv = log_open_file (stderr, prog, priority, options);
    if (rv == -1) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to setup logging to stderr");
    }
}
