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


#ifndef MUNGE_HKDF_H
#define MUNGE_HKDF_H

#include <sys/types.h>
#include <munge.h>


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct hkdf_ctx hkdf_ctx_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

hkdf_ctx_t * hkdf_ctx_create (void);

void hkdf_ctx_destroy (hkdf_ctx_t *ctxp);

int hkdf_ctx_set_md (hkdf_ctx_t *ctxp, munge_mac_t md);

int hkdf_ctx_set_key (hkdf_ctx_t *ctxp, const void *key, size_t keylen);

int hkdf_ctx_set_salt (hkdf_ctx_t *ctxp, const void *salt, size_t saltlen);

int hkdf_ctx_set_info (hkdf_ctx_t *ctxp, const void *info, size_t infolen);

int hkdf (hkdf_ctx_t *ctxp, void *dst, size_t *dstlenp);


#endif /* !MUNGE_HKDF_H */
