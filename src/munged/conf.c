/*****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2018 Lawrence Livermore National Security, LLC.
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>                  /* include before in.h for bsd */
#include <netinet/in.h>                 /* include before inet.h for bsd */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <munge.h>
#include <netdb.h>                      /* for gethostbyname() */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>                  /* for MAXHOSTNAMELEN */
#include <sys/socket.h>                 /* for AF_INET */
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "conf.h"
#include "license.h"
#include "lock.h"
#include "log.h"
#include "md.h"
#include "missing.h"                    /* for inet_ntop() */
#include "munge_defs.h"
#include "path.h"
#include "str.h"
#include "version.h"
#include "zip.h"


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

#define OPT_ADVICE              256
#define OPT_KEY_FILE            257
#define OPT_NUM_THREADS         258
#define OPT_AUTH_SERVER         259
#define OPT_AUTH_CLIENT         260
#define OPT_GROUP_CHECK         261
#define OPT_GROUP_UPDATE        262
#define OPT_SYSLOG              263
#define OPT_BENCHMARK           264
#define OPT_MAX_TTL             265
#define OPT_PID_FILE            266
#define OPT_LOG_FILE            267
#define OPT_SEED_FILE           268
#define OPT_TRUSTED_GROUP       269
#define OPT_LAST                270

const char * const short_opts = ":hLVfFMsS:v";

#include <getopt.h>
struct option long_opts[] = {
    { "help",              no_argument,       NULL, 'h'               },
    { "license",           no_argument,       NULL, 'L'               },
    { "version",           no_argument,       NULL, 'V'               },
    { "force",             no_argument,       NULL, 'f'               },
    { "foreground",        no_argument,       NULL, 'F'               },
    { "mlockall",          no_argument,       NULL, 'M'               },
    { "stop",              no_argument,       NULL, 's'               },
    { "socket",            required_argument, NULL, 'S'               },
    { "verbose",           no_argument,       NULL, 'v'               },
    { "advice",            no_argument,       NULL, OPT_ADVICE        },
#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
    { "auth-server-dir",   required_argument, NULL, OPT_AUTH_SERVER   },
    { "auth-client-dir",   required_argument, NULL, OPT_AUTH_CLIENT   },
#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */
    { "benchmark",         no_argument,       NULL, OPT_BENCHMARK     },
    { "group-check-mtime", required_argument, NULL, OPT_GROUP_CHECK   },
    { "group-update-time", required_argument, NULL, OPT_GROUP_UPDATE  },
    { "key-file",          required_argument, NULL, OPT_KEY_FILE      },
    { "log-file",          required_argument, NULL, OPT_LOG_FILE      },
    { "max-ttl",           required_argument, NULL, OPT_MAX_TTL       },
    { "num-threads",       required_argument, NULL, OPT_NUM_THREADS   },
    { "pid-file",          required_argument, NULL, OPT_PID_FILE      },
    { "seed-file",         required_argument, NULL, OPT_SEED_FILE     },
    { "syslog",            no_argument,       NULL, OPT_SYSLOG        },
    { "trusted-group",     required_argument, NULL, OPT_TRUSTED_GROUP },
    {  NULL,               0,                 NULL, 0                 }
};


/*****************************************************************************
 *  Internal Prototypes
 *****************************************************************************/

static void _process_stop (conf_t conf);

static int _send_signal (pid_t pid, int signum, int msecs);

static int _conf_open_keyfile (const char *keyfile, int got_force);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

conf_t conf = NULL;                     /* global configuration struct       */


/*****************************************************************************
 *  External Functions
 *****************************************************************************/

conf_t
create_conf (void)
{
    conf_t conf;

    if (!(conf = malloc (sizeof (struct conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate conf");
    }
    conf->ld = -1;
    conf->got_benchmark = 0;
    conf->got_clock_skew = 1;
    conf->got_force = 0;
    conf->got_foreground = 0;
    conf->got_group_stat = !! MUNGE_GROUP_STAT_FLAG;
    conf->got_stop = 0;
    conf->got_mlockall = 0;
    conf->got_root_auth = !! MUNGE_AUTH_ROOT_ALLOW_FLAG;
    conf->got_socket_retry = !! MUNGE_SOCKET_RETRY_FLAG;
    conf->got_syslog = 0;
    conf->got_verbose = 0;
    conf->def_cipher = MUNGE_DEFAULT_CIPHER;
    conf->def_zip = zip_select_default_type (MUNGE_DEFAULT_ZIP);
    conf->def_mac = MUNGE_DEFAULT_MAC;
    conf->def_ttl = MUNGE_DEFAULT_TTL;
    conf->max_ttl = MUNGE_MAXIMUM_TTL;
    /*
     *  FIXME: Add support for default realm.
     */
    conf->config_name = NULL;
    conf->lockfile_fd = -1;
    conf->lockfile_name = NULL;

    if (!(conf->logfile_name = strdup (MUNGE_LOGFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy logfile name string");
    }
    if (!(conf->pidfile_name = strdup (MUNGE_PIDFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy pidfile name string");
    }
    if (!(conf->socket_name = strdup (MUNGE_SOCKET_NAME))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy socket name string");
    }
    if (!(conf->seed_name = strdup (MUNGE_SEEDFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy seed name string");
    }
    if (!(conf->key_name = strdup (MUNGE_KEYFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy key name string");
    }
    conf->dek_key = NULL;
    conf->dek_key_len = 0;
    conf->mac_key = NULL;
    conf->mac_key_len = 0;
    memset (&conf->addr, 0, sizeof (conf->addr));
    conf->gids = NULL;
    conf->gids_update_secs = MUNGE_GROUP_UPDATE_SECS;
    conf->nthreads = MUNGE_THREADS;
    conf->auth_server_dir = NULL;
    conf->auth_client_dir = NULL;
    conf->auth_rnd_bytes = MUNGE_AUTH_RND_BYTES;

#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
    if (!(conf->auth_server_dir = strdup (MUNGE_AUTH_SERVER_DIR))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy auth-server-dir default string");
    }
    if (!(conf->auth_client_dir = strdup (MUNGE_AUTH_CLIENT_DIR))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy auth-client-dir default string");
    }
#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */

    return (conf);
}


void
destroy_conf (conf_t conf, int do_unlink)
{
    assert (conf != NULL);
    assert (conf->ld < 0);              /* sock_destroy() already called */
    assert (conf->lockfile_fd < 0);

    if (conf->config_name) {
        free (conf->config_name);
        conf->config_name = NULL;
    }
    if (conf->lockfile_name) {
        free (conf->lockfile_name);
        conf->lockfile_name = NULL;
    }
    if (conf->logfile_name) {
        free (conf->logfile_name);
        conf->logfile_name = NULL;
    }
    if (conf->pidfile_name) {
        if (do_unlink) {
            (void) unlink (conf->pidfile_name);
        }
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
    long  l;
    char *p;

    assert (conf != NULL);

    opterr = 0;                         /* suppress default getopt err msgs */

    prog = (prog = strrchr (argv[0], '/')) ? prog + 1 : argv[0];

    for (;;) {

        c = getopt_long (argc, argv, short_opts, long_opts, NULL);

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
            case 'M':
                conf->got_mlockall = 1;
                break;
            case 's':
                conf->got_stop = 1;
                break;
            case 'S':
                if (conf->socket_name)
                    free (conf->socket_name);
                if (!(conf->socket_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy socket name string");
                break;
            case 'v':
                conf->got_verbose = 1;
                break;
            case OPT_ADVICE:
                printf ("Don't Panic!\n");
                exit (42);
#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
            case OPT_AUTH_SERVER:
                if (conf->auth_server_dir)
                    free (conf->auth_server_dir);
                if (!(conf->auth_server_dir = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy auth-server-dir cmdline string");
                break;
            case OPT_AUTH_CLIENT:
                if (conf->auth_client_dir)
                    free (conf->auth_client_dir);
                if (!(conf->auth_client_dir = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy auth-client-dir cmdline string");
                break;
#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */
            case OPT_BENCHMARK:
                conf->got_benchmark = 1;
                break;
            case OPT_GROUP_CHECK:
                errno = 0;
                l = strtol (optarg, &p, 10);
                if (((errno == ERANGE) && ((l == LONG_MIN) || (l == LONG_MAX)))
                        || (optarg == p) || (*p != '\0')) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid value \"%s\" for group-check-mtime", optarg);
                }
                conf->got_group_stat = !! l;
                break;
            case OPT_GROUP_UPDATE:
                errno = 0;
                l = strtol (optarg, &p, 10);
                if (((errno == ERANGE) && ((l == LONG_MIN) || (l == LONG_MAX)))
                        || (optarg == p) || (*p != '\0')
                        || (l < INT_MIN) || (l > INT_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid value \"%s\" for group-update-time", optarg);
                }
                conf->gids_update_secs = l;
                break;
            case OPT_KEY_FILE:
                if (conf->key_name)
                    free (conf->key_name);
                if (!(conf->key_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy key-file name string");
                break;
            case OPT_LOG_FILE:
                if (conf->logfile_name)
                    free (conf->logfile_name);
                if (!(conf->logfile_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy log-file name string");
                break;
            case OPT_MAX_TTL:
                l = strtol (optarg, &p, 10);
                if (((errno == ERANGE) && ((l == LONG_MIN) || (l == LONG_MAX)))
                        || (optarg == p) || (*p != '\0')
                        || (l < 1) || (l > MUNGE_MAXIMUM_TTL)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid value \"%s\" for max-ttl", optarg);
                }
                conf->max_ttl = l;
                break;
            case OPT_NUM_THREADS:
                errno = 0;
                l = strtol (optarg, &p, 10);
                if (((errno == ERANGE) && ((l == LONG_MIN) || (l == LONG_MAX)))
                        || (optarg == p) || (*p != '\0')
                        || (l <= 0) || (l > INT_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid value \"%s\" for num-threads", optarg);
                }
                conf->nthreads = l;
                break;
            case OPT_PID_FILE:
                if (conf->pidfile_name)
                    free (conf->pidfile_name);
                if (!(conf->pidfile_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy pid-file name string");
                break;
            case OPT_SEED_FILE:
                if (conf->seed_name)
                    free (conf->seed_name);
                if (!(conf->seed_name = strdup (optarg)))
                    log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                        "Failed to copy seed-file name string");
                break;
            case OPT_SYSLOG:
                conf->got_syslog = 1;
                break;
            case OPT_TRUSTED_GROUP:
                if (path_set_trusted_group (optarg) < 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid value \"%s\" for trusted-group", optarg);
                }
                break;
            case '?':
                if (optopt > 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid option \"-%c\"", optopt);
                }
                else if (optind > 1) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid option \"%s\"", argv[optind - 1]);
                }
                else {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to process command-line");
                }
                break;
            case ':':
                if ((optind > 1)
                        && (strncmp (argv[optind - 1], "--", 2) == 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Missing argument for option \"%s\"",
                        argv[optind - 1]);
                }
                else if (optopt > 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Missing argument for option \"-%c\"", optopt);
                }
                else {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to process command-line");
                }
                break;
            default:
                if ((optind > 1)
                        && (strncmp (argv[optind - 1], "--", 2) == 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unimplemented option \"%s\"", argv[optind - 1]);
                }
                else {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unimplemented option \"-%c\"", c);
                }
                break;
        }
    }
    if (argv[optind]) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Unrecognized parameter \"%s\"", argv[optind]);
    }
    if (conf->got_stop) {
        _process_stop (conf);
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
            "Force daemon to run if possible");

    printf ("  %*s %s\n", w, "-F, --foreground",
            "Run daemon in the foreground (do not fork)");

    printf ("  %*s %s\n", w, "-M, --mlockall",
            "Lock all pages in memory");

    printf ("  %*s %s\n", w, "-s, --stop",
            "Stop daemon bound to socket");

    printf ("  %*s %s [%s]\n", w, "-S, --socket=PATH",
            "Specify local socket", MUNGE_SOCKET_NAME);

    printf ("  %*s %s\n", w, "-v, --verbose",
            "Be verbose");

    printf ("\n");

#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
    printf ("  %*s %s [%s]\n", w, "--auth-server-dir=DIR",
            "Specify auth-server directory", MUNGE_AUTH_SERVER_DIR);

    printf ("  %*s %s [%s]\n", w, "--auth-client-dir=DIR",
            "Specify auth-client directory", MUNGE_AUTH_CLIENT_DIR);
#endif /* AUTH_METHOD_RECVFD_MKFIFO || AUTH_METHOD_RECVFD_MKNOD */

    printf ("  %*s %s\n", w, "--benchmark",
            "Disable timers to reduce noise while benchmarking");

    printf ("  %*s Specify whether to check \"%s\" mtime [%d]\n",
            w, "--group-check-mtime=BOOL", GIDS_GROUP_FILE,
            MUNGE_GROUP_STAT_FLAG);

    printf ("  %*s %s [%d]\n", w, "--group-update-time=INT",
            "Specify seconds between group info updates",
            MUNGE_GROUP_UPDATE_SECS);

    printf ("  %*s %s [%s]\n", w, "--key-file=PATH",
            "Specify key file", MUNGE_KEYFILE_PATH);

    printf ("  %*s %s [%s]\n", w, "--log-file=PATH",
            "Specify log file", MUNGE_LOGFILE_PATH);

    printf ("  %*s %s [%d]\n", w, "--max-ttl=INT",
            "Specify maximum time-to-live (in seconds)", MUNGE_MAXIMUM_TTL);

    printf ("  %*s %s [%d]\n", w, "--num-threads=INT",
            "Specify number of threads to spawn", MUNGE_THREADS);

    printf ("  %*s %s [%s]\n", w, "--pid-file=PATH",
            "Specify PID file", MUNGE_PIDFILE_PATH);

    printf ("  %*s %s [%s]\n", w, "--seed-file=PATH",
            "Specify PRNG seed file", MUNGE_SEEDFILE_PATH);

    printf ("  %*s %s\n", w, "--syslog",
            "Redirect log messages to syslog");

    printf ("  %*s %s\n", w, "--trusted-group=GROUP",
            "Specify trusted group/GID for directory checks");

    printf ("\n");
    return;
}


void
create_subkeys (conf_t conf)
{
    int fd;
    int n;
    int n_total;
    unsigned char buf[1024];
    md_ctx dek_ctx;
    md_ctx mac_ctx;

    assert (conf != NULL);
    assert (conf->dek_key == NULL);
    assert (conf->mac_key == NULL);

    /*  Allocate memory for subkeys.
     */
    if ((conf->dek_key_len = md_size (MUNGE_MAC_SHA1)) <= 0) {
        log_err (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to determine DEK key length");
    }
    if (!(conf->dek_key = malloc (conf->dek_key_len))) {
        log_err (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to allocate %d bytes for cipher subkey",
            conf->dek_key_len);
    }
    if ((conf->mac_key_len = md_size (MUNGE_MAC_SHA1)) <= 0) {
        log_err (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to determine MAC key length");
    }
    if (!(conf->mac_key = malloc (conf->mac_key_len))) {
        log_err (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to allocate %d bytes for MAC subkey",
            conf->mac_key_len);
    }
    if (md_init (&dek_ctx, MUNGE_MAC_SHA1) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to compute subkeys: Cannot init md ctx");
    }
    /*  Compute keyfile's message digest.
     */
    fd = _conf_open_keyfile (conf->key_name, conf->got_force);
    assert (fd >= 0);

    n_total = 0;
    for (;;) {
        n = read (fd, buf, sizeof (buf));
        if (n == 0)
            break;
        if ((n < 0) && (errno == EINTR))
            continue;
        if (n < 0)
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to read keyfile \"%s\"", conf->key_name);
        if (md_update (&dek_ctx, buf, n) < 0)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to compute subkeys: Cannot update md ctx");
        n_total += n;
    }
    if (close (fd) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to close keyfile \"%s\"", conf->key_name);
    }
    if (n_total < MUNGE_KEY_LEN_MIN_BYTES) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Keyfile must be at least %d bytes", MUNGE_KEY_LEN_MIN_BYTES);
    }
    if (md_copy (&mac_ctx, &dek_ctx) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to compute subkeys: Cannot copy md ctx");
    }
    /*  Append "1" to keyfile in order to compute cipher subkey.
     */
    n = conf->dek_key_len;
    if ( (md_update (&dek_ctx, "1", 1) < 0)
      || (md_final (&dek_ctx, conf->dek_key, &n) < 0)
      || (md_cleanup (&dek_ctx) < 0) ) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to compute cipher subkey");
    }
    assert (n <= conf->dek_key_len);

    /*  Append "2" to keyfile in order to compute mac subkey.
     */
    n = conf->mac_key_len;
    if ( (md_update (&mac_ctx, "2", 1) < 0)
      || (md_final (&mac_ctx, conf->mac_key, &n) < 0)
      || (md_cleanup (&mac_ctx) < 0) ) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to compute MAC subkey");
    }
    assert (n <= conf->mac_key_len);

    return;
}


void
lookup_ip_addr (conf_t conf)
{
    char hostname [MAXHOSTNAMELEN];
    char ip_addr_buf [INET_ADDRSTRLEN];
    struct hostent *hptr;

    if (gethostname (hostname, sizeof (hostname)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to determine hostname");
    }
    hostname [sizeof (hostname) - 1] = '\0';

    /*  The origin IP address is embedded within the credential metadata,
     *    but is informational and not required for successful authentication.
     *    The in_addr is zeroed here so that if name resolution fails, the IPv4
     *    address will be set to 0.0.0.0.
     */
    memset (&conf->addr, 0, sizeof (conf->addr));

    /*  The gethostbyname() call is not reentrant, but that's ok because:
     *    1. there is only one thread active at this point, and
     *    2. this is the only call to gethostbyname().
     *  Note that gethostbyname() DOES NOT set errno.
     */
    if (!(hptr = gethostbyname (hostname))) {
        log_msg (LOG_WARNING, "Failed to resolve host \"%s\"", hostname);
    }
    else if (sizeof (conf->addr) != hptr->h_length) {
        log_msg (LOG_WARNING,
                "Failed to resolve host \"%s\": not an IPv4 address (len=%d)",
                hostname, hptr->h_length);
    }
    else {
        memcpy (&conf->addr, hptr->h_addr_list[0], sizeof (conf->addr));
    }

    if (!inet_ntop (AF_INET, &conf->addr, ip_addr_buf, sizeof (ip_addr_buf))) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to convert IP address for \"%s\"", hostname);
    }

    log_msg (LOG_NOTICE, "Running on \"%s\" (%s)",
            (hptr && hptr->h_name) ? hptr->h_name : hostname, ip_addr_buf);
    return;
}


/*****************************************************************************
 *  Internal Functions
 *****************************************************************************/

static void
_process_stop (conf_t conf)
{
/*  Processes the -s/--stop option.
 *  A series of SIGTERMs are sent to the process holding the write-lock.
 *    If the process fails to terminate, a final SIGKILL is sent.
 */
    pid_t pid;
    int   signum;
    int   msecs;
    int   i;
    int   rv;

    assert (conf != NULL);
    assert (MUNGE_SIGNAL_ATTEMPTS > 0);
    assert (MUNGE_SIGNAL_DELAY_MSECS > 0);

    pid = lock_query (conf);
    if (pid <= 0) {
        if (conf->got_verbose) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to signal daemon bound to socket \"%s\""
                    ": Lockfile not found", conf->socket_name);
        }
        exit (EXIT_FAILURE);
    }
    rv = kill (pid, 0);
    if (rv < 0) {
        if (conf->got_verbose) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to signal daemon bound to socket \"%s\" (pid %d)",
                    conf->socket_name, pid);
        }
        exit (EXIT_FAILURE);
    }
    signum = SIGTERM;
    msecs = 0;
    for (i = 0; i < (MUNGE_SIGNAL_ATTEMPTS + 1); i++) {
        if (i == MUNGE_SIGNAL_ATTEMPTS) {
            signum = SIGKILL;           /* Kill me harder! */
        }
        msecs += MUNGE_SIGNAL_DELAY_MSECS;
        rv = _send_signal (pid, signum, msecs);
        if (rv == 0) {
            if (conf->got_verbose) {
                log_msg (LOG_NOTICE,
                        "%s daemon bound to socket \"%s\" (pid %d)",
                        (signum == SIGTERM) ? "Terminated" : "Killed",
                        conf->socket_name, pid);
            }
            exit (EXIT_SUCCESS);
        }
    }
    if (conf->got_verbose) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
                "Failed to terminate daemon bound to socket \"%s\" (pid %d)",
                conf->socket_name, pid);
    }
    exit (EXIT_FAILURE);
}


static int
_send_signal (pid_t pid, int signum, int msecs)
{
/*  Sends the signal [signum] to the process specified by [pid].
 *  Returns 1 if the process is still running after a delay of [msecs],
 *    or 0 if the process cannot be found.
 */
    struct timespec ts;
    int             rv;

    assert (pid > 0);
    assert (signum > 0);
    assert (msecs > 0);

    log_msg (LOG_DEBUG, "Signaling pid %d with sig %d and %dms delay",
            pid, signum, msecs);

    rv = kill (pid, signum);
    if (rv < 0) {
        if (errno == ESRCH) {
            return (0);
        }
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to signal daemon (pid %d, sig %d)", pid, signum);
    }
    ts.tv_sec = msecs / 1000;
    ts.tv_nsec = (msecs % 1000) * 1000 * 1000;
retry:
    rv = nanosleep (&ts, &ts);
    if (rv < 0) {
        if (errno == EINTR) {
            goto retry;
        }
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to sleep while awaiting signal result");
    }
    rv = kill (pid, 0);
    if (rv < 0) {
        if (errno == ESRCH) {
            return (0);
        }
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to check daemon (pid %d, sig 0)", pid);
    }
    return (1);
}


static int
_conf_open_keyfile (const char *keyfile, int got_force)
{
/*  Returns a valid file-descriptor to the opened [keyfile], or dies trying.
 */
    int          is_symlink;
    struct stat  st;
    int          n;
    char         keydir [PATH_MAX];
    char         ebuf [1024];
    int          fd;

    if ((keyfile == NULL) || (*keyfile == '\0')) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Keyfile name is undefined");
    }
    is_symlink = (lstat (keyfile, &st) == 0) ? S_ISLNK (st.st_mode) : 0;

    if (stat (keyfile, &st) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check keyfile \"%s\"", keyfile);
    }
    if (!S_ISREG (st.st_mode)) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Keyfile is insecure: \"%s\" must be a regular file (type=%07o)",
            keyfile, (st.st_mode & S_IFMT));
    }
    if (is_symlink) {
        log_err_or_warn (got_force,
            "Keyfile is insecure: \"%s\" should not be a symbolic link",
            keyfile);
    }
    if (st.st_uid != geteuid ()) {
        log_err_or_warn (got_force,
            "Keyfile is insecure: \"%s\" should be owned by UID %u instead of "
            "UID %u", keyfile, (unsigned) geteuid (), (unsigned) st.st_uid);
    }
    if (st.st_mode & (S_IRGRP | S_IWGRP)) {
        log_err_or_warn (got_force,
            "Keyfile is insecure: \"%s\" should not be readable or writable "
            "by group (perms=%04o)", keyfile, (st.st_mode & ~S_IFMT));
    }
    if (st.st_mode & (S_IROTH | S_IWOTH)) {
        log_err_or_warn (got_force,
            "Keyfile is insecure: \"%s\" should not be readable or writable "
            "by other (perms=%04o)", keyfile, (st.st_mode & ~S_IFMT));
    }
    /*  Ensure keyfile dir is secure against modification by others.
     */
    if (path_dirname (keyfile, keydir, sizeof (keydir)) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine dirname of keyfile \"%s\"", keyfile);
    }
    n = path_is_secure (keydir, ebuf, sizeof (ebuf), PATH_SECURITY_NO_FLAGS);
    if (n < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to check keyfile dir \"%s\": %s", keydir, ebuf);
    }
    else if (n == 0) {
        log_err_or_warn (got_force, "Keyfile is insecure: %s", ebuf);
    }
    /*  Open keyfile for reading only.
     */
    if ((fd = open (keyfile, O_RDONLY)) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to open keyfile \"%s\"", keyfile);
    }
    return (fd);
}
