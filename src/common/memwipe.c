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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

/*  Request C11 Annex K declarations (memset_s) from <string.h> when supported.
 *  This macro must be defined before the first inclusion of <string.h>.
 */
#ifdef NEED_STDC_WANT_LIB_EXT1
#  define __STDC_WANT_LIB_EXT1__ 1
#endif /* NEED_STDC_WANT_LIB_EXT1 */

#include <assert.h>
#include <stddef.h>

/*  explicit_bzero() may be declared by either <strings.h> (FreeBSD) or
 *  <string.h> (all other tested systems).  The other functions are
 *  declared in <string.h>.  Include both for simplicity.
 */
#if HAVE_MEMSET_EXPLICIT \
    || HAVE_EXPLICIT_BZERO \
    || HAVE_EXPLICIT_MEMSET \
    || HAVE_MEMSET_S
#  include <string.h>
#  include <strings.h>
#endif

#include "memwipe.h"

/**
 *  Overwrite the first [n] bytes of [v] with the null byte in a manner that
 *  resists compiler dead store elimination (DSE).  This reduces the risk that
 *  sensitive data remains readable in memory after use, but cannot guarantee
 *  complete erasure -- copies may exist in registers, stack scratch space, or
 *  other locations invisible to the compiler.
 */
void
memwipe (void *v, size_t n)
{
    assert (v != NULL);

#if HAVE_MEMSET_EXPLICIT /* C23; glibc >= 2.43, FreeBSD >= 15, NetBSD >= 11 */
    (void) memset_explicit (v, 0, n);
#elif HAVE_EXPLICIT_BZERO /* glibc >= 2.25, FreeBSD >= 11, OpenBSD >= 5.5 */
    explicit_bzero (v, n);
#elif HAVE_EXPLICIT_MEMSET /* NetBSD >= 7 */
    (void) explicit_memset (v, 0, n);
#elif HAVE_MEMSET_S /* C11 Annex K; FreeBSD >= 11.1, macOS */
    (void) memset_s (v, n, 0, n);       /* smax == n: wipe entire buffer */
#else
/*  Dead store elimination can drop attempts to wipe sensitive data.
 *  Writing through a volatile pointer prevents this optimization within a
 *  single translation unit, but link-time optimization (LTO) may defeat it.
 */
    volatile unsigned char *p = (volatile unsigned char *) v;

    while (n--) {
        *p++ = 0;
    }
#endif /* HAVE_MEMSET_EXPLICIT */
}
