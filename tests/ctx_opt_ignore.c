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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <munge.h>
#include "tap.h"


void
test_opt (int opt, const char *name)
{
    int i;
    munge_ctx_t ctx;
    munge_err_t err;

    ctx = munge_ctx_create ();
    if (!ctx) {
        BAIL_OUT ("failed to create munge ctx");
    }
    /* check default */
    i = -1; err = munge_ctx_get (ctx, opt, &i);
    ok (err == EMUNGE_SUCCESS, "get %s opt default", name);
    ok (i == 0, "%s is disabled", name);

    /* check enable */
    err = munge_ctx_set (ctx, opt, 1);
    ok (err == EMUNGE_SUCCESS, "set %s opt to 1", name);
    i = -1; err = munge_ctx_get (ctx, opt, &i);
    ok (err == EMUNGE_SUCCESS, "get %s after setting to 1", name);
    ok (i == 1, "%s is enabled", name);

    /* check disable */
    err = munge_ctx_set (ctx, opt, 0);
    ok (err == EMUNGE_SUCCESS, "set %s opt to 0", name);
    i = -1; err = munge_ctx_get (ctx, opt, &i);
    ok (err == EMUNGE_SUCCESS, "get %s after setting to 0", name);
    ok (i == 0, "%s is disabled", name);

    /* check positive value */
    err = munge_ctx_set (ctx, opt, INT_MAX);
    ok (err == EMUNGE_SUCCESS, "set %s opt to maximum int", name);
    i = -1; err = munge_ctx_get (ctx, opt, &i);
    ok (err == EMUNGE_SUCCESS, "get %s after setting to maximum int", name);
    ok (i == 1, "%s is enabled", name);

    /* check negative value */
    err = munge_ctx_set (ctx, opt, -1);
    ok (err == EMUNGE_SUCCESS, "set %s opt to negative int", name);
    i = -1; err = munge_ctx_get (ctx, opt, &i);
    ok (err == EMUNGE_SUCCESS, "get %s after setting to negative int", name);
    ok (i == 1, "%s is enabled", name);

    munge_ctx_destroy (ctx);
}


int
main (int argc, char *argv[])
{
    plan (NO_PLAN);
    test_opt (MUNGE_OPT_IGNORE_TTL, "ignore-ttl");
    test_opt (MUNGE_OPT_IGNORE_REPLAY, "ignore-replay");
    done_testing ();
    exit (EXIT_SUCCESS);
}

