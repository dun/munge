/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://home.gna.org/munge/>.
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include "license.h"


static const char *license_string = \
    "Welcome to the MUNGE Uid 'N' Gid Emporium (MUNGE).\n"                    \
    "http://home.gna.org/munge/\n"                                            \
    "\n"                                                                      \
    "Written by Chris Dunlap <cdunlap@llnl.gov>.\n"                           \
    "Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.\n"    \
    "Copyright (C) 2002-2007 The Regents of the University of California.\n"  \
    "\n"                                                                      \
    "MUNGE is free software; you can redistribute it and/or modify it\n"      \
    "under the terms of the GNU General Public License as published by\n"     \
    "the Free Software Foundation; either version 2 of the License, or\n"     \
    "(at your option) any later version.\n"                                   \
    "\n";


void
display_license (void)
{
    printf ("%s", license_string);
    return;
}
