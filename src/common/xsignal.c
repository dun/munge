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

#include <signal.h>
#include <string.h>
#include <munge.h>
#include "log.h"
#include "xsignal.h"


void
xsignal_ignore (int sig)
{
    struct sigaction sa;
    int              rv;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    rv = sigfillset (&sa.sa_mask);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to initialize signal set to full");
    }
    rv = sigaction (sig, &sa, NULL);
    if (rv == -1) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to ignore signal %d (%s)",
                sig, strsignal (sig));
    }
    return;
}
