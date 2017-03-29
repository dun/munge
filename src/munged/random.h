/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2017 Lawrence Livermore National Security, LLC.
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


#ifndef RANDOM_H
#define RANDOM_H

#include "path.h"


int random_init (const char *seed, path_security_flag_t base_pathsec);
/*
 *  Initializes the PRNG from the [seed] file.
 *  If [seed] does not exist or provide sufficient entropy,
 *    the PRNG will be seeded from a secure source.
 *  Returns 1 if [seed] provides sufficient entropy, 0 if it provides
 *    insufficient entropy but no errors were detected, or -1 on error.
 */

void random_fini (const char *seed);
/*
 *  Cleans-up the PRNG, writing the current state out to the [seed] file
 *    if one is specified.
 */

void random_add (const void *buf, int n);
/*
 *  Adds [n] bytes of entropy from [buf] to the PRNG state.
 */

void random_bytes (unsigned char *buf, int n);
/*
 *  Places [n] bytes of cryptographically strong pseudo-random data into [buf].
 */

void random_pseudo_bytes (unsigned char *buf, int n);
/*
 *  Places [n] bytes of pseudo-random data into [buf].
 *  This should not be used for purposes such as key generation.
 */

void random_stir (void);
/*
 *  Stirs the PRNG entropy pool.
 */


#endif /* !RANDOM_H */
