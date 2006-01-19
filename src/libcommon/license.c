/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  UCRL-CODE-155910.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include "license.h"


static const char *license_string = \
    "Welcome to the Munge Uid 'N' Gid Emporium (MUNGE).\n\n"                  \
    "Copyright (C) 2002-2006 The Regents of the University of California.\n"  \
    "Produced at Lawrence Livermore National Laboratory.\n"                   \
    "Written by Chris Dunlap <cdunlap@llnl.gov>.\n"                           \
    "http://www.llnl.gov/linux/munge/\n"                                      \
    "UCRL-CODE-155910\n\n"                                                    \
    "Munge is free software; you can redistribute it and/or modify it\n"      \
    "under the terms of the GNU General Public License as published by\n"     \
    "the Free Software Foundation.\n\n";


void
display_license (void)
{
    printf ("%s", license_string);
    return;
}
