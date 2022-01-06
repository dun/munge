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


#ifndef MUNGEKEY_CONF_H
#define MUNGEKEY_CONF_H


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

typedef struct conf {
    unsigned    do_create:1;            /* flag to create new key            */
    unsigned    do_force:1;             /* flag to force overwriting key     */
    unsigned    do_verbose:1;           /* flag to be verbose                */
    char       *key_path;               /* pathname of keyfile               */
    int         key_num_bytes;          /* number of bytes for key creation  */
} conf_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t * create_conf (void);

void destroy_conf (conf_t *confp);

void parse_cmdline (conf_t *confp, int argc, char **argv);


#endif /* !MUNGEKEY_CONF_H */
