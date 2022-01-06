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
    unsigned        got_benchmark:1;    /* flag for BENCHMARK option         */
    unsigned        got_clock_skew:1;   /* flag for allowing clock skew      */
    unsigned        got_force:1;        /* flag for FORCE option             */
    unsigned        got_foreground:1;   /* flag for FOREGROUND option        */
    unsigned        got_group_stat:1;   /* flag for gids stat'ing /etc/group */
    unsigned        got_stop:1;         /* flag for stopping daemon          */
    unsigned        got_mlockall:1;     /* flag for locking all memory pages */
    unsigned        got_root_auth:1;    /* flag if root can decode any cred  */
    unsigned        got_socket_retry:1; /* flag for allowing decode retries  */
    unsigned        got_syslog:1;       /* flag if logging to syslog instead */
    unsigned        got_verbose:1;      /* flag for being verbose            */
    munge_cipher_t  def_cipher;         /* default cipher type               */
    munge_zip_t     def_zip;            /* default compression type          */
    munge_mac_t     def_mac;            /* default message auth code type    */
    munge_ttl_t     def_ttl;            /* default time-to-live in seconds   */
    munge_ttl_t     max_ttl;            /* maximum time-to-live in seconds   */
    char           *cwd;                /* current working dir at startup    */
    char           *config_name;        /* configuration filename            */
    int             lockfile_fd;        /* daemon lockfile fd                */
    char           *lockfile_name;      /* daemon lockfile name              */
    char           *logfile_name;       /* daemon logfile name               */
    char           *pidfile_name;       /* daemon pidfile name               */
    char           *socket_name;        /* unix domain socket filename       */
    char           *seed_name;          /* random seed filename              */
    char           *key_name;           /* symmetric key filename            */
    unsigned char  *dek_key;            /* subkey for cipher ops             */
    int             dek_key_len;        /* length of cipher subkey           */
    unsigned char  *mac_key;            /* subkey for mac ops                */
    int             mac_key_len;        /* length of mac subkey              */
    char           *origin_name;        /* origin addr hostname/IP string    */
    char           *origin_ifname;      /* origin addr n/w interface name    */
    struct in_addr  addr;               /* origin addr in n/w byte order     */
    gids_t          gids;               /* supplementary group information   */
    int             gids_update_secs;   /* gids update interval in seconds   */
    int             nthreads;           /* num threads for processing creds  */
    char           *auth_server_dir;    /* dir in which to create auth pipe  */
    char           *auth_client_dir;    /* dir in which to create auth file  */
    int             auth_rnd_bytes;     /* num rnd bytes in auth pipe name   */
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

void destroy_conf (conf_t conf, int do_unlink);

void parse_cmdline (conf_t conf, int argc, char **argv);

void process_conf (conf_t conf);

void write_origin_addr (conf_t conf);

void create_subkeys (conf_t conf);


#endif /* !MUNGE_CONF_H */
