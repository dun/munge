/*****************************************************************************
 *  $Id: license.c,v 1.2 2003/02/18 19:46:19 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************
 *  Refer to "license.h" for documentation on public functions.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>


static const char *license = \
    "Copyright (C) 2002-2003 The Regents of the University of California.\n"  \
    "Produced at Lawrence Livermore National Laboratory.\n"                   \
    "Written by Chris Dunlap <cdunlap@llnl.gov>.\n"                           \
    "http://www.llnl.gov/linux/munge/\n"                                      \
    "UCRL-CODE-2003-???\n\n"                                                  \
    "Munge is free software; you can redistribute it and/or modify it\n"      \
    "under the terms of the GNU General Public License as published by\n"     \
    "the Free Software Foundation.\n";


void
display_license (void)
{
    printf ("%s", license);
    return;
}
