/*****************************************************************************
 *  $Id: conf.c,v 1.15 2004/03/19 23:39:01 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003-2004 The Regents of the University of California.
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
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>                 /* include before inet.h for bsd */
#include <arpa/inet.h>                  /* for inet_ntoa() */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <munge.h>
#include <netdb.h>                      /* for gethostbyname() */
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>                  /* for MAXHOSTNAMELEN */
#include <unistd.h>
#include "conf.h"
#include "license.h"
#include "log.h"
#include "md.h"
#include "munge_defs.h"
#include "replay.h"
#include "str.h"
#include "zip.h"


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

#if HAVE_GETOPT_H
#  include <getopt.h>
struct option opt_table[] = {
    { "help",       0, NULL, 'h' },
    { "license",    0, NULL, 'L' },
    { "version",    0, NULL, 'V' },
    { "force",      0, NULL, 'f' },
    { "foreground", 0, NULL, 'F' },
    { "socket",     1, NULL, 'S' },
    {  NULL,        0, NULL,  0  }
};
#endif /* HAVE_GETOPT_H */
                                                                                
const char * const opt_string = "hLVfFS:";


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

conf_t
create_conf (void)
{
    conf_t conf;

    /*  FIXME: On ENOMEM, log which malloc op failed.
     */
    if (!(conf = malloc (sizeof (struct conf))))
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf");
    conf->ld = -1;
    conf->got_clock_skew = 1;
    conf->got_force = 0;
    conf->got_foreground = 0;
    conf->def_cipher = MUNGE_DEFAULT_CIPHER;
    conf->def_zip = zip_select_default_type (MUNGE_DEFAULT_ZIP);
    conf->def_mac = MUNGE_DEFAULT_MAC;
    conf->def_ttl = MUNGE_DEFAULT_TTL;
    conf->max_ttl = MUNGE_MAXIMUM_TTL;
    /*
     *  FIXME: Add support for default realm.
     */
    /*
     *  FIXME: Get file lock on configuration filename?
     */
    conf->config_name = NULL;
    if (!(conf->socket_name = strdup (MUNGE_SOCKET_NAME)))
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Cannot dup socket name string");
    /*
     *  FIXME: Add support for random seed filename.
     */
    if (!(conf->seed_name = strdup (MUNGED_RANDOM_SEED)))
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Cannot dup seed name string");
    /*
     *  FIXME: Add support for configuring key filename.
     */
    if (!(conf->key_name = strdup (MUNGED_SECRET_KEY)))
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Cannot dup key name string");
    conf->dek_key = NULL;
    conf->dek_key_len = 0;
    conf->mac_key = NULL;
    conf->mac_key_len = 0;

    replay_init ();

    return (conf);
}


void
destroy_conf (conf_t conf)
{
    assert (conf != NULL);
    assert (conf->ld < 0);              /* munge_sock_destroy already called */

    if (conf->config_name) {
        free (conf->config_name);
        conf->config_name = NULL;
    }
    if (conf->socket_name) {
        free (conf->socket_name);
        conf->socket_name = NULL;
    }
    if (conf->seed_name) {
        free (conf->seed_name);
        conf->seed_name = NULL;
    }
    if (conf->key_name) {
        free (conf->key_name);
        conf->key_name = NULL;
    }
    if (conf->dek_key) {
        memburn (conf->dek_key, 0, conf->dek_key_len);
        free (conf->dek_key);
        conf->dek_key = NULL;
    }
    if (conf->mac_key) {
        memburn (conf->mac_key, 0, conf->mac_key_len);
        free (conf->mac_key);
        conf->mac_key = NULL;
    }
    free (conf);

    replay_fini ();

    return;
}


void
parse_cmdline (conf_t conf, int argc, char **argv)
{
    char *prog;
    int   c;

    opterr = 0;                         /* suppress default getopt err msgs */

    prog = (prog = strrchr (argv[0], '/')) ? prog + 1 : argv[0];

    for (;;) {
#if HAVE_GETOPT_LONG
        c = getopt_long (argc, argv, opt_string, opt_table, NULL);
#else  /* !HAVE_GETOPT_LONG */
        c = getopt (argc, argv, opt_string);
#endif /* !HAVE_GETOPT_LONG */

        if (c == -1) {                  /* reached end of option list */
            break;
        }
        switch (c) {
            case 'h':
                display_help (prog);
                exit (EMUNGE_SUCCESS);
                break;
            case 'L':
                display_license ();
                exit (EMUNGE_SUCCESS);
                break;
            case 'V':
                printf ("%s-%s\n", PACKAGE, VERSION);
                exit (EMUNGE_SUCCESS);
                break;
            case 'f':
                conf->got_force = 1;
                break;
            case 'F':
                conf->got_foreground = 1;
                break;
            case 'S':
                if  (conf->socket_name)
                    free (conf->socket_name);
                if (!(conf->socket_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Cannot dup socket name string");
                break;
            case '?':
                if (optopt > 0)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid option \"-%c\"", optopt);
                else
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid option \"%s\"", argv[optind - 1]);
                break;
            default:
                log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Unimplemented option \"%s\"", argv[optind - 1]);
                break;
        }
    }
    if (argv[optind]) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unrecognized parameter \"%s\"", argv[optind]);
    }
    return;
}


void
display_help (char *prog)
{
/*  Displays a help message describing the command-line options.
 */
#if HAVE_GETOPT_LONG
    const int got_long = 1;
#else  /* !HAVE_GETOPT_LONG */
    const int got_long = 0;
#endif /* !HAVE_GETOPT_LONG */
    const int w = -21;                  /* pad for width of option string */

    assert (prog != NULL);

    printf ("Usage: %s [OPTIONS]\n", prog);
    printf ("\n");

    printf ("  %*s %s\n", w, (got_long ? "-h, --help" : "-h"),
            "Display this help");

    printf ("  %*s %s\n", w, (got_long ? "-L, --license" : "-L"),
            "Display license information");

    printf ("  %*s %s\n", w, (got_long ? "-V, --version" : "-V"),
            "Display version information");

    printf ("  %*s %s\n", w, (got_long ? "-f, --force" : "-f"),
            "Force process to run if possible");

    printf ("  %*s %s\n", w, (got_long ? "-F, --foreground" : "-F"),
            "Run process in the foreground (do not fork)");

    printf ("  %*s %s\n", w, (got_long ? "-S, --socket=STRING" : "-S STRING"),
            "Specify local domain socket");

    printf ("\n");

    return;
}


void
create_subkeys (conf_t conf)
{
    const EVP_MD *md = EVP_sha1();
    int fd;
    int n;
    unsigned char buf[1024];
    md_ctx dek_ctx;
    md_ctx mac_ctx;

    assert (conf != NULL);
    assert (conf->dek_key == NULL);
    assert (conf->mac_key == NULL);

    /*  Allocate memory for subkeys.
     */
    conf->dek_key_len = md_size (md);
    if (!(conf->dek_key = malloc (conf->dek_key_len))) {
        log_err (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate %d bytes for cipher subkey",
            conf->dek_key_len);
    }
    conf->mac_key_len = md_size (md); {
    if (!(conf->mac_key = malloc (conf->mac_key_len)))
        log_err (EMUNGE_NO_MEMORY, LOG_ERR,
            "Unable to allocate %d bytes for mac subkey",
            conf->mac_key_len);
    }
    if (md_init (&dek_ctx, md) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unable to compute subkeys: Cannot init md ctx");
    }
    /*  Open keyfile.
     */
    if ((conf->key_name == NULL) || (*conf->key_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "No keyfile was specified");
    }
    /*  FIXME: Ignore keyfile if it does not have sane permissions.
     */
    if ((fd = open (conf->key_name, O_RDONLY)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to open keyfile \"%s\"", conf->key_name);
    }
    /*  Compute keyfile's message digest.
     */
    for (;;) {
        n = read (fd, buf, sizeof (buf));
        if (n == 0)
            break;
        if ((n < 0) && (errno == EINTR))
            continue;
        if (n < 0)
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to read keyfile \"%s\"", conf->key_name);
        if (md_update (&dek_ctx, buf, n) < 0)
            log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to compute subkeys");
    }
    if (close (fd) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to close keyfile \"%s\"", conf->key_name);
    }
    if (md_copy (&mac_ctx, &dek_ctx) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unable to compute subkeys: Cannot copy md ctx");
    }
    /*  Append "1" to keyfile in order to compute cipher subkey.
     */
    if ( (md_update (&dek_ctx, "1", 1) < 0)
      || (md_final (&dek_ctx, conf->dek_key, &n) < 0)
      || (md_cleanup (&dek_ctx) < 0) ) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to compute cipher subkey");
    }
    assert (n == conf->dek_key_len);

    /*  Append "2" to keyfile in order to compute mac subkey.
     */
    if ( (md_update (&mac_ctx, "2", 1) < 0)
      || (md_final (&mac_ctx, conf->mac_key, &n) < 0)
      || (md_cleanup (&mac_ctx) < 0) ) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to compute mac subkey");
    }
    assert (n == conf->mac_key_len);

    return;
}


void
lookup_ip_addr (conf_t conf)
{
    char hostname [MAXHOSTNAMELEN];
    struct hostent *hptr;
    char *host_str;
    char *ip_str;

    if (gethostname (hostname, sizeof (hostname)) < 0)
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to determine hostname");
    /*
     *  The man page doesn't say what happens if the buffer is overrun,
     *    so guarantee buffer NUL-termination just in case.
     */
    hostname [sizeof (hostname) - 1] = '\0';
    /*
     *  The gethostbyname() call is not reentrant, but that's ok because:
     *    1. there is only one thread active at this point, and
     *    2. this is the only call to gethostbyname().
     *
     *  Note that gethostbyname() DOES NOT set errno.
     */
    if (!(hptr = gethostbyname (hostname))) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unable to resolve host \"%s\"", hostname);
    }
    memcpy (&conf->addr, hptr->h_addr_list[0], sizeof (conf->addr));
    /*
     *  The inet_ntoa() call is not reentrant, but that's ok (as above).
     *
     *  Yes, I realize inet_ntoa() is dated, but inet_ntop() isn't
     *    commonplace yet, and this one invocation isn't worth autoconfing.
     *    Besides, we don't need to be thread-safe just yet.
     */
    host_str = hptr->h_name;
    ip_str = inet_ntoa (conf->addr);
    log_msg (LOG_NOTICE, "Running on host \"%s\" (%s)", host_str, ip_str);
    return;
}
