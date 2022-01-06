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


#ifndef RANDOM_H
#define RANDOM_H


int random_init (const char *seed_path);
/*
 *  Initializes the PRNG from [seed_path] and other sources.
 *  Returns 1 if sufficient entropy is gathered, 0 if insufficient entropy
 *    is gathered but no errors were detected, or -1 on error.
 */

void random_fini (const char *seed_path);
/*
 *  Shuts down the PRNG, writing the state of the entropy pool to [seed_path].
 */

void random_add (const void *buf, int n);
/*
 *  Adds [n] bytes of entropy from [buf] to the PRNG entropy pool.
 */

void random_bytes (void *buf, int n);
/*
 *  Places [n] bytes of cryptographically-strong pseudo-random data into [buf].
 */

void random_pseudo_bytes (void *buf, int n);
/*
 *  Places [n] bytes of pseudo-random data into [buf].
 *  This should not be used for purposes such as key generation.
 */


#endif /* !RANDOM_H */
