/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2003-2006 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory.
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>                 /* include before inet.h for bsd */
#include <arpa/inet.h>                  /* for inet_ntop() */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <munge.h>
#include <netdb.h>                      /* for gethostbyname() */
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>                  /* for MAXHOSTNAMELEN */
#include <sys/socket.h>                 /* for AF_INET */
#include <unistd.h>
#include "auth_policy.h"
#include "conf.h"
#include "license.h"
#include "log.h"
#include "md.h"
#include "missing.h"
#include "munge_defs.h"
#include "str.h"
#include "version.h"
#include "zip.h"


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

#  include <getopt.h>
struct option opt_table[] = {
    { "help",       0, NULL, 'h' },
    { "license",    0, NULL, 'L' },
    { "version",    0, NULL, 'V' },
    { "force",      0, NULL, 'f' },
    { "foreground", 0, NULL, 'F' },
    { "socket",     1, NULL, 'S' },
    { "advice",     0, NULL, 'A' },
    { "key-file",        1, NULL, '0' },
    { "num-threads",     1, NULL, '1' },
#ifdef MUNGE_AUTH_RECVFD
    { "auth-server-dir", 1, NULL, '2' },
    { "auth-client-dir", 1, NULL, '3' },
#endif /* MUNGE_AUTH_RECVFD */
    {  NULL,        0, NULL,  0  }
};

const char * const opt_string = "hLVfFS:";


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

conf_t conf = NULL;                     /* global configuration struct       */


/*****************************************************************************
 *  Extern Functions
 *****************************************************************************/

conf_t
create_conf (void)
{
    conf_t conf;

    /*  FIXME: On ENOMEM, log which malloc op failed.
     */
    if (!(conf = malloc (sizeof (struct conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf");
    }
    conf->ld = -1;
    conf->got_clock_skew = 1;
    conf->got_force = 0;
    conf->got_foreground = 0;
    conf->got_group_stat = MUNGE_GROUP_STAT_FLAG;
    conf->got_replay_retry = MUNGE_REPLAY_RETRY_FLAG;
    conf->got_root_auth = MUNGE_AUTH_ROOT_ALLOW_FLAG;
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
    if (!(conf->pidfile_name = strdup (MUNGED_PIDFILE))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Cannot dup pidfile name string");
    }
    if (!(conf->socket_name = strdup (MUNGE_SOCKET_NAME))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Cannot dup socket name string");
    }
    if (!(conf->seed_name = strdup (MUNGED_RANDOM_SEED))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Cannot dup seed name string");
    }
    if (!(conf->key_name = strdup (MUNGED_SECRET_KEY))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Cannot dup key name string");
    }
    conf->dek_key = NULL;
    conf->dek_key_len = 0;
    conf->mac_key = NULL;
    conf->mac_key_len = 0;
    conf->nthreads = MUNGE_THREADS;

#ifdef MUNGE_AUTH_RECVFD

    if (!(conf->auth_server_dir = strdup (MUNGE_AUTH_SERVER_DIR))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Cannot dup auth-server-dir default string");
    }
    if (!(conf->auth_client_dir = strdup (MUNGE_AUTH_CLIENT_DIR))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Cannot dup auth-client-dir default string");
    }
#endif /* MUNGE_AUTH_RECVFD */

    conf->auth_rnd_bytes = MUNGE_AUTH_RND_BYTES;

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
    if (conf->pidfile_name) {
        (void) unlink (conf->pidfile_name);
        free (conf->pidfile_name);
        conf->pidfile_name = NULL;
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
    if (conf->auth_server_dir) {
        free (conf->auth_server_dir);
        conf->auth_server_dir = NULL;
    }
    if (conf->auth_client_dir) {
        free (conf->auth_client_dir);
        conf->auth_client_dir = NULL;
    }
    free (conf);

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

        c = getopt_long (argc, argv, opt_string, opt_table, NULL);

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
                display_version ();
                exit (EMUNGE_SUCCESS);
                break;
            case 'f':
                conf->got_force = 1;
                break;
            case 'F':
                conf->got_foreground = 1;
                break;
            case 'S':
                if (conf->socket_name)
                    free (conf->socket_name);
                if (!(conf->socket_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Cannot dup socket name string");
                break;
            case 'A':
                printf ("Don't Panic!\n");
                exit (42);
            /* Begin deprecated cmdline opts */
            case '0':
                if (conf->key_name)
                    free (conf->key_name);
                if (!(conf->key_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Cannot dup key-file name string");
                break;
            case '1':
                if ((c = atoi (optarg)) > 0)
                    conf->nthreads = c;
                break;
#ifdef MUNGE_AUTH_RECVFD
            case '2':
                if (conf->auth_server_dir)
                    free (conf->auth_server_dir);
                if (!(conf->auth_server_dir = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Cannot dup auth-server-dir cmdline string");
                break;
            case '3':
                if (conf->auth_client_dir)
                    free (conf->auth_client_dir);
                if (!(conf->auth_client_dir = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Cannot dup auth-client-dir cmdline string");
                break;
#endif /* MUNGE_AUTH_RECVFD */
            /* End deprecated cmdline opts */
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
    const int w = -24;                  /* pad for width of option string */

    assert (prog != NULL);

    printf ("Usage: %s [OPTIONS]\n", prog);
    printf ("\n");

    printf ("  %*s %s\n", w, "-h, --help",
            "Display this help");

    printf ("  %*s %s\n", w, "-L, --license",
            "Display license information");

    printf ("  %*s %s\n", w, "-V, --version",
            "Display version information");

    printf ("\n");

    printf ("  %*s %s\n", w, "-f, --force",
            "Force process to run if possible");

    printf ("  %*s %s\n", w, "-F, --foreground",
            "Run process in the foreground (do not fork)");

    printf ("  %*s %s [%s]\n", w, "-S, --socket=PATH",
            "Specify local socket", MUNGE_SOCKET_NAME);

    printf ("\n");

    /* Begin deprecated cmdline opts */

#ifdef MUNGE_AUTH_RECVFD
    printf ("  %*s %s [%s]\n", w, "--auth-server-dir=DIR",
            "Specify auth-server directory", MUNGE_AUTH_SERVER_DIR);

    printf ("  %*s %s [%s]\n", w, "--auth-client-dir=DIR",
            "Specify auth-client directory", MUNGE_AUTH_CLIENT_DIR);
#endif /* MUNGE_AUTH_RECVFD */

    printf ("  %*s %s [%s]\n", w, "--key-file=PATH",
            "Specify secret key file", MUNGED_SECRET_KEY);

    printf ("  %*s %s [%d]\n", w, "--num-threads=INT",
            "Specify number of threads to spawn", MUNGE_THREADS);
    /* End deprecated cmdline opts */

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
    /*  Open key-file.
     */
    if ((conf->key_name == NULL) || (*conf->key_name == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "No key-file was specified");
    }
    /*  FIXME: Ignore key-file if it does not have sane permissions.
     */
    if ((fd = open (conf->key_name, O_RDONLY)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to open key-file \"%s\"", conf->key_name);
    }
    /*  Compute key-file's message digest.
     */
    for (;;) {
        n = read (fd, buf, sizeof (buf));
        if (n == 0)
            break;
        if ((n < 0) && (errno == EINTR))
            continue;
        if (n < 0)
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to read key-file \"%s\"", conf->key_name);
        if (md_update (&dek_ctx, buf, n) < 0)
            log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to compute subkeys");
    }
    if (close (fd) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Unable to close key-file \"%s\"", conf->key_name);
    }
    if (md_copy (&mac_ctx, &dek_ctx) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unable to compute subkeys: Cannot copy md ctx");
    }
    /*  Append "1" to key-file in order to compute cipher subkey.
     */
    if ( (md_update (&dek_ctx, "1", 1) < 0)
      || (md_final (&dek_ctx, conf->dek_key, &n) < 0)
      || (md_cleanup (&dek_ctx) < 0) ) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to compute cipher subkey");
    }
    assert (n == conf->dek_key_len);

    /*  Append "2" to key-file in order to compute mac subkey.
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
    char ip_buf [INET_ADDRSTRLEN];
    struct hostent *hptr;

    if (gethostname (hostname, sizeof (hostname)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to determine hostname");
    }
    /*  The man page doesn't say what happens if the buffer is overrun,
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
    assert (sizeof (conf->addr) == hptr->h_length);
    memcpy (&conf->addr, hptr->h_addr_list[0], sizeof (conf->addr));

    if (!inet_ntop (AF_INET, &conf->addr, ip_buf, sizeof (ip_buf))) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to determine ip address");
    }
    log_msg (LOG_NOTICE, "Running on host \"%s\" (%s)", hptr->h_name, ip_buf);
    return;
}
