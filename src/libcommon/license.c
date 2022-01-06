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
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include "license.h"


/*  The license string was broken into an array of strings in order to keep
 *    below the 509-character limit that ISO C90 compilers are required to
 *    support (detected when compiling with -pedantic).
 */
static const char *license_text[] = { \
    "Welcome to the MUNGE Uid 'N' Gid Emporium (MUNGE).",
    "https://dun.github.io/munge/",
    "",
    "Written by Chris Dunlap <cdunlap@llnl.gov>.",
    "Copyright (C) 2007-2022 Lawrence Livermore National Security, LLC.",
    "Copyright (C) 2002-2007 The Regents of the University of California.",
    "",
    "MUNGE is free software: you can redistribute it and/or modify it under",
    "the terms of the GNU General Public License as published by the Free",
    "Software Foundation, either version 3 of the License,"
        " or (at your option)",
    "any later version.",
    "",
    "Additionally for the MUNGE library (libmunge), you can redistribute",
    "it and/or modify it under the terms of the GNU Lesser General Public",
    "License as published by the Free Software Foundation, either version 3",
    "of the License, or (at your option) any later version.",
    "",
    "MUNGE is distributed in the hope that it will be useful, but WITHOUT",
    "ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or",
    "FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License",
    "and GNU Lesser General Public License for more details.",
    "",
    NULL
};


void
display_license (void)
{
    const char **pp;

    for (pp = license_text; *pp != NULL; pp++) {
        printf ("%s\n", *pp);
    }
    return;
}
