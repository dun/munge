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

#ifndef MUNGE_DIAG_H
#define MUNGE_DIAG_H

/**
 *  Macros for suppressing compiler diagnostics at specific call sites.
 *
 *  DIAG_PUSH saves the current diagnostic state.
 *  DIAG_POP restores the previous diagnostic state.
 *  DIAG_OFF(w) disables the warning specified by the quoted string [w].
 *
 *  Example:
 *    DIAG_PUSH
 *    DIAG_OFF ("-Wcast-qual")
 *    ptr = (char *) const_ptr;
 *    DIAG_POP
 *
 *  Note: DIAG_PRAGMA is an internal helper macro; do not use it directly.
 *  Note: GCC diagnostic pragmas inside functions require v4.6 or later.
 *        Clang sets __GNUC__ == 4 and __GNUC_MINOR__ == 2 regardless of
 *          the actual Clang version, causing the GCC >= 4.6 gate to fail,
 *          so Clang is detected separately via __clang__.
 *        Clang push/pop support requires v3.0 or later (earliest confirmed).
 */

#if (defined (__GNUC__) \
            && ((__GNUC__ > 4) \
                || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))) \
        || (defined (__clang__) && (__clang_major__ >= 3))
#  define DIAG_PRAGMA(x)        _Pragma (#x)
#  define DIAG_PUSH             DIAG_PRAGMA (GCC diagnostic push)
#  define DIAG_POP              DIAG_PRAGMA (GCC diagnostic pop)
#  define DIAG_OFF(w)           DIAG_PRAGMA (GCC diagnostic ignored w)
#else
#  define DIAG_PUSH             /* empty */
#  define DIAG_POP              /* empty */
#  define DIAG_OFF(w)           /* empty */
#endif /* (__GNUC__ >= 4.6) || (__clang__ >= 3.0) */

#endif /* MUNGE_DIAG_H */
