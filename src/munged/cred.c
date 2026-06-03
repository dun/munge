/******************************************************************************
 *  Copyright (C) 2007-2026 Lawrence Livermore National Security, LLC.
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
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "cred.h"

#include "m_msg.h"
#include "memwipe.h"

#include <munge.h>

#include <assert.h>
#include <stdlib.h>                     /* calloc, free */


munge_cred_t
cred_create (m_msg_t m)
{
    munge_cred_t c;

    assert (m != NULL);

    if (!(c = calloc (1, sizeof *c))) {
        m_msg_set_err (m, EMUNGE_NO_MEMORY, NULL);
        return NULL;
    }
    c->version = MUNGE_CRED_VERSION;
    c->msg = m;
    return c;
}


/**
 *  Destroy the credential [c], releasing all associated memory.
 *
 *  Securely erase [inner_mem] (may hold plaintext) and [dek].  All other
 *  fields are either public wire-format data or public identifiers.
 */
void
cred_destroy (munge_cred_t c)
{
    if (!c) {
        return;
    }
    if (c->outer_mem) {
        assert (c->outer_mem_len > 0);
        free (c->outer_mem);
    }
    if (c->inner_mem) {
        assert (c->inner_mem_len > 0);
        memwipe_and_free (c->inner_mem, (size_t) c->inner_mem_len);
    }
    if (c->realm_mem) {
        assert (c->realm_mem_len > 0);
        free (c->realm_mem);
    }
    assert (c->dek_len >= 0);
    assert (c->dek_len <= (int) sizeof c->dek);
    memwipe (c->dek, (size_t) c->dek_len);
    free (c);
}
