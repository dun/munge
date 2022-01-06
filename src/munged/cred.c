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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "cred.h"
#include "m_msg.h"
#include "munge_defs.h"
#include "str.h"


munge_cred_t
cred_create (m_msg_t m)
{
    munge_cred_t c;

    assert (m != NULL);

    if (!(c = calloc (1, sizeof (*c)))) {
        m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL);
        return (NULL);
    }
    c->version = MUNGE_CRED_VERSION;
    c->msg = m;
    return (c);
}


void
cred_destroy (munge_cred_t c)
{
    if (!c) {
        return;
    }
    if (c->outer_mem) {
        assert (c->outer_mem_len > 0);
        memset (c->outer_mem, 0, c->outer_mem_len);
        free (c->outer_mem);
    }
    if (c->inner_mem) {
        assert (c->inner_mem_len > 0);
        memset (c->inner_mem, 0, c->inner_mem_len);
        free (c->inner_mem);
    }
    if (c->realm_mem) {
        assert (c->realm_mem_len > 0);
        memset (c->realm_mem, 0, c->realm_mem_len);
        free (c->realm_mem);
    }
    memburn (c, 0, sizeof (*c));        /* nuke the msg dek */
    free (c);
    return;
}
