/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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
 *  You should have received a copy of the GNU General Public License;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 *  Suite 330, Boston, MA  02111-1307  USA.
 *****************************************************************************/


#ifndef MUNGE_CONF_H
#define MUNGE_CONF_H

#include <inttypes.h>
#include <munge.h>
#include <netinet/in.h>
#include "gids.h"


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

struct conf {
    int             ld;                 /* listening socket descriptor       */
    unsigned        got_clock_skew:1;   /* flag for allowing clock skew      */
    unsigned        got_force:1;        /* flag for FORCE option             */
    unsigned        got_foreground:1;   /* flag for FOREGROUND option        */
    unsigned        got_group_stat:1;   /* flag for gids stat'ing /etc/group */
    unsigned        got_replay_retry:1; /* flag for allowing decode retries  */
    unsigned        got_root_auth:1;    /* flag if root can decode any cred  */
    munge_cipher_t  def_cipher;         /* default cipher type               */
    munge_zip_t     def_zip;            /* default compression type          */
    munge_mac_t     def_mac;            /* default message auth code type    */
    munge_ttl_t     def_ttl;            /* default time-to-live              */
    munge_ttl_t     max_ttl;            /* default time-to-live              */
    char           *config_name;        /* configuration filename            */
    char           *socket_name;        /* unix domain socket filename       */
    char           *seed_name;          /* random seed filename              */
    char           *key_name;           /* symmetric key filename            */
    unsigned char  *dek_key;            /* subkey for cipher ops             */
    int             dek_key_len;        /* length of cipher subkey           */
    unsigned char  *mac_key;            /* subkey for mac ops                */
    int             mac_key_len;        /* length of mac subkey              */
    struct in_addr  addr;               /* IPv4 addr in n/w byte order       */
    gids_t          gids;               /* supplementary group information   */
    int             nthreads;           /* num threads for processing creds  */
    char           *auth_pipe_dir;      /* dir in which to create auth pipe  */
    int             auth_pipe_rnd_bytes;/* num rnd bytes in auth pipe name   */
};

typedef struct conf * conf_t;


/*****************************************************************************
 *  External Varables
 *****************************************************************************/

extern conf_t conf;                     /* defined in conf.c                 */


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t create_conf (void);

void destroy_conf (conf_t conf);

void parse_cmdline (conf_t conf, int argc, char **argv);

void display_help (char *prog);

void create_subkeys (conf_t conf);

void lookup_ip_addr (conf_t conf);


#endif /* !MUNGE_CONF_H */
