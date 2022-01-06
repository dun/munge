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


#ifndef CRYPTO_H
#define CRYPTO_H


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#if HAVE_LIBGCRYPT && HAVE_OPENSSL
#  error "Libgcrypt and OpenSSL are mutually-exclusive"
#endif

#include <sys/types.h>


void crypto_init (void);
/*
 *  Initializes the cryptographic subsystem.
 */

void crypto_fini (void);
/*
 *  Shuts down the cryptographic subsystem.
 */

int crypto_memcmp (const void *s1, const void *s2, size_t n);
/*
 *  Compares the first [n] bytes of the memory regions [s1] and [s2] in an
 *    amount of time dependent upon the length [n], but independent of the
 *    contents of either [s1] or [s2].
 *  Returns 0 if the memory regions are equal, or non-zero otherwise.
 */


#endif /* !CRYPTO_H */
