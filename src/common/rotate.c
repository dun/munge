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
 *  <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <stdlib.h>
#include "rotate.h"


/*****************************************************************************
 *  Public Functions
 *****************************************************************************/

/*  Rotate the reference [*up] by [n] bits to the left.
 *    Bits rotated off the left end are wrapped-around to the right.
 */
void
rotate_left (unsigned *up, size_t n)
{
    unsigned ntotal;
    unsigned mask;
    unsigned move;

    assert (up != NULL);

    ntotal = sizeof (*up) * 8;
    n %= ntotal;
    if (n == 0) {
        return;
    }
    mask = ~0 << (ntotal - n);
    move = *up & mask;
    move >>= ntotal - n;
    *up <<= n;
    *up |= move;
}


/*  Rotate the reference [*up] by [n] bits to the right.
 *    Bits rotated off the right end are wrapped-around to the left.
 */
void
rotate_right (unsigned *up, size_t n)
{
    unsigned ntotal;
    unsigned mask;
    unsigned move;

    assert (up != NULL);

    ntotal = sizeof (*up) * 8;
    n %= ntotal;
    if (n == 0) {
        return;
    }
    mask = ~0 >> (ntotal - n);
    move = *up & mask;
    move <<= ntotal - n;
    *up >>= n;
    *up |= move;
}
