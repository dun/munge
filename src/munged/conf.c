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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <arpa/inet.h>                  /* for inet_ntop() */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>                 /* for AF_INET */
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>
#include "clock.h"
#include "conf.h"
#include "license.h"
#include "lock.h"
#include "log.h"
#include "md.h"
#include "missing.h"                    /* for inet_ntop() */
#include "munge_defs.h"
#include "net.h"
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
#define OPT_ORIGIN              270
#define OPT_LAST                271

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
    { "origin",            required_argument, NULL, OPT_ORIGIN        },
    { "pid-file",          required_argument, NULL, OPT_PID_FILE      },
    { "seed-file",         required_argument, NULL, OPT_SEED_FILE     },
    { "syslog",            no_argument,       NULL, OPT_SYSLOG        },
    { "trusted-group",     required_argument, NULL, OPT_TRUSTED_GROUP },
    {  NULL,               0,                 NULL, 0                 }
};


/*****************************************************************************
 *  Internal Prototypes
 *****************************************************************************/

static void _conf_set_cwd (conf_t conf);

static void _conf_display_help (char *prog);

static void _conf_set_string (char **str_p, const char *val, const char *cwd,
        const char *dsc);

static void _conf_process_stop (conf_t conf);

static int _conf_send_signal (pid_t pid, int signum, int msecs);

static void _conf_sleep (int msecs);

static void _conf_set_origin_addr (conf_t conf);

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

    _conf_set_cwd (conf);

    if (!(conf->logfile_name = strdup (MUNGE_LOGFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy log-file name default string");
    }
    if (!(conf->pidfile_name = strdup (MUNGE_PIDFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy pid-file name default string");
    }
    if (!(conf->socket_name = strdup (MUNGE_SOCKET_NAME))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy socket name default string");
    }
    if (!(conf->seed_name = strdup (MUNGE_SEEDFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy seed-file name default string");
    }
    if (!(conf->key_name = strdup (MUNGE_KEYFILE_PATH))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to copy key-file name default string");
    }
    conf->dek_key = NULL;
    conf->dek_key_len = 0;
    conf->mac_key = NULL;
    conf->mac_key_len = 0;
    conf->origin_name = NULL;
    conf->origin_ifname = NULL;
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
    int rv;

    assert (conf != NULL);
    assert (conf->ld < 0);              /* sock_destroy() already called */
    assert (conf->lockfile_fd < 0);

    if (conf->cwd) {
        free (conf->cwd);
        conf->cwd = NULL;
    }
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
            do {
                rv = unlink (conf->pidfile_name);
            } while ((rv < 0) && (errno == EINTR));

            if (rv < 0) {
                log_msg (LOG_WARNING, "Failed to remove pidfile \"%s\": %s",
                        conf->pidfile_name, strerror (errno));
            }
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
    if (conf->origin_name) {
        free (conf->origin_name);
        conf->origin_name = NULL;
    }
    if (conf->origin_ifname) {
        free (conf->origin_ifname);
        conf->origin_ifname = NULL;
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
                _conf_display_help (prog);
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
                _conf_set_string (&conf->socket_name, optarg, conf->cwd,
                        "socket name");
                break;
            case 'v':
                conf->got_verbose = 1;
                break;
            case OPT_ADVICE:
                printf ("Don't Panic!\n");
                exit (42);
#if defined(AUTH_METHOD_RECVFD_MKFIFO) || defined(AUTH_METHOD_RECVFD_MKNOD)
            case OPT_AUTH_SERVER:
                _conf_set_string (&conf->auth_server_dir, optarg, conf->cwd,
                        "auth-server-dir name");
                break;
            case OPT_AUTH_CLIENT:
                _conf_set_string (&conf->auth_client_dir, optarg, conf->cwd,
                        "auth-client-dir name");
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
                _conf_set_string (&conf->key_name, optarg, conf->cwd,
                        "key-file name");
                break;
            case OPT_LOG_FILE:
                _conf_set_string (&conf->logfile_name, optarg, conf->cwd,
                        "log-file name");
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
            case OPT_ORIGIN:
                _conf_set_string (&conf->origin_name, optarg, NULL, "origin");
                break;
            case OPT_PID_FILE:
                _conf_set_string (&conf->pidfile_name, optarg, conf->cwd,
                        "pid-file name");
                break;
            case OPT_SEED_FILE:
                _conf_set_string (&conf->seed_name, optarg, conf->cwd,
                        "seed-file name");
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
}


void
process_conf (conf_t conf)
{
/*  Process the configuration.
 */
    assert (conf != NULL);

    if (conf->got_stop) {
        _conf_process_stop (conf);
    }
    _conf_set_origin_addr (conf);
    return;
}


void
write_origin_addr (conf_t conf)
{
/*  Write a log message indicating the origin address that will be encoded into
 *    the credential metadata.
 */
    char buf[INET_ADDRSTRLEN];

    assert (conf != NULL);

    if (!inet_ntop (AF_INET, &conf->addr, buf, sizeof (buf))) {
        log_msg (LOG_WARNING, "Failed to convert origin address to a string");
    }
    else if (conf->origin_ifname != NULL) {
        log_msg (LOG_INFO, "Set origin address to %s (%s)", buf,
                conf->origin_ifname);
    }
    else {
        log_msg (LOG_INFO, "Set origin address to %s", buf);
    }
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


/*****************************************************************************
 *  Internal Functions
 *****************************************************************************/

static void
_conf_set_cwd (conf_t conf)
{
/*  Set the current working directory in order to fix relative paths so these
 *    locations can still be accessed after chdir() is called.
 */
    char  buf [PATH_MAX];
    char *rv;

    rv = getcwd (buf, sizeof (buf));

    /*  Starting in Linux 2.6.36, the path returned by getcwd() will be
     *    prefixed with "(unreachable)" if the current directory is not below
     *    the root directory of the current process.  With glibc 2.27 onwards,
     *    this will instead result in failure with ENOENT.
     *  Since relative paths break the getcwd() API contract requiring an
     *    absolute path, convert anything not starting with an absolute path
     *    (like "(unreachable)") to ENOENT.
     */
    if ((rv != NULL) && (buf[0] != '/')) {
        rv = NULL;
        errno = ENOENT;
    }

    if (rv == NULL) {
        conf->cwd = NULL;
        if (errno == ERANGE) {
            log_msg (LOG_WARNING,
                    "Failed to set current working directory: "
                    "Exceeded %lu-byte buffer", sizeof (buf));
        }
        else {
            log_msg (LOG_WARNING,
                    "Failed to set current working directory: %s",
                    strerror (errno));
        }
    }
    else {
        conf->cwd = strdup (buf);
        if (conf->cwd == NULL) {
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
                    "Failed to copy current working directory string");
        }
    }
}


static void
_conf_display_help (char *prog)
{
/*  Displays a help message describing the command-line options.
 */
    const int w = -25;                  /* pad for width of option string */

    assert (prog != NULL);

    printf ("Usage: %s [OPTIONS]\n", prog);
    printf ("\n");

    printf ("  %*s %s\n", w, "-h, --help",
            "Display this help message");

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

    printf ("  %*s %s [%d]\n", w, "--group-update-time=SECS",
            "Specify seconds between group info updates",
            MUNGE_GROUP_UPDATE_SECS);

    printf ("  %*s %s [%s]\n", w, "--key-file=PATH",
            "Specify key file", MUNGE_KEYFILE_PATH);

    printf ("  %*s %s [%s]\n", w, "--log-file=PATH",
            "Specify log file", MUNGE_LOGFILE_PATH);

    printf ("  %*s %s [%d]\n", w, "--max-ttl=SECS",
            "Specify maximum time-to-live (in seconds)", MUNGE_MAXIMUM_TTL);

    printf ("  %*s %s [%d]\n", w, "--num-threads=INT",
            "Specify number of threads to spawn", MUNGE_THREADS);

    printf ("  %*s %s\n", w, "--origin=ADDR",
            "Specify origin address via hostname/IPaddr/interface");

    printf ("  %*s %s [%s]\n", w, "--pid-file=PATH",
            "Specify PID file", MUNGE_PIDFILE_PATH);

    printf ("  %*s %s [%s]\n", w, "--seed-file=PATH",
            "Specify PRNG seed file", MUNGE_SEEDFILE_PATH);

    printf ("  %*s %s\n", w, "--syslog",
            "Redirect log messages to syslog");

    printf ("  %*s %s\n", w, "--trusted-group=GID",
            "Specify trusted group/GID for directory checks");

    printf ("\n");
    return;
}


static void
_conf_set_string (char **str_p, const char *val, const char *cwd,
        const char *dsc)
{
/*  Set the string referenced by [str_p] to the string value [val], freeing
 *    an existing string pointed to by [str_p] if needed.  If [val] is not an
 *    absolute pathname and the current working directory string [cwd] is set,
 *    that string will be prepended to [val].
 *  The description string [dsc] will be used in the error message if needed.
 */
    assert (str_p != NULL);
    assert (val != NULL);
    assert (dsc != NULL);

    if (*str_p != NULL) {
        free (*str_p);
    }
    *str_p = (val[0] == '/' || cwd == NULL)
        ? strdup (val)
        : strdupf ("%s/%s", cwd, val);

    if (*str_p == NULL) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to copy %s string", dsc);
    }
}


static void
_conf_process_stop (conf_t conf)
{
/*  Process the -s/--stop option.
 *  A SIGTERM is sent to the process holding the write-lock.
 *    A SIGKILL is sent afterwards if the process fails to terminate.
 */
    pid_t pid;
    int   rv;

    assert (conf != NULL);
    assert (MUNGE_SIGNAL_WAIT_MSECS > 0);

    /*  Obtain pid of daemon bound to socket.
     */
    pid = lock_query (conf);
    if (pid <= 0) {
        if (conf->got_verbose) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to query socket lockfile \"%s\": %s (%s)",
                    conf->lockfile_name,
                    (pid == 0) ? "Lock not held" : strerror (errno),
                    "Cannot find running process");
        }
        exit (EXIT_FAILURE);
    }
    /*  Terminate.
     */
    rv = _conf_send_signal (pid, SIGTERM, MUNGE_SIGNAL_WAIT_MSECS);
    if (rv == 0) {
        if (conf->got_verbose) {
            log_msg (LOG_NOTICE,
                    "Terminated daemon bound to socket \"%s\" (pid %d)",
                    conf->socket_name, pid);
        }
        exit (EXIT_SUCCESS);
    }
    /*  Kill.
     */
    rv = _conf_send_signal (pid, SIGKILL, MUNGE_SIGNAL_WAIT_MSECS);
    if (rv == 0) {
        if (conf->got_verbose) {
            log_msg (LOG_NOTICE,
                    "Killed daemon bound to socket \"%s\" (pid %d)",
                    conf->socket_name, pid);
        }
        exit (EXIT_SUCCESS);
    }
    /*  Fail.
     */
    log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to terminate daemon bound to socket \"%s\" (pid %d)",
            conf->socket_name, pid);
    exit (EXIT_FAILURE);
}


static int
_conf_send_signal (pid_t pid, int signum, int msecs)
{
/*  Send the signal [signum] to the process specified by [pid].
 *  Return 1 if the process is still running after a delay of [msecs],
 *    or 0 if the process has terminated.
 */
    struct timespec wait_abstime;
    int             rv;
    int             sig;

    assert (pid > 0);
    assert (signum > 0);
    assert (msecs > 0);
    assert (MUNGE_SIGNAL_CHECK_MSECS > 0);

    rv = clock_get_timespec (&wait_abstime, msecs);
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to get wait time for termination");
    }
    sig = signum;
    while (1) {
        rv = kill (pid, sig);
        if (rv < 0) {
            if (errno == ESRCH) {
                return (0);
            }
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to signal daemon (pid %d, sig %d)", pid, sig);
        }
        rv = clock_is_timespec_expired (&wait_abstime);
        if (rv < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Failed to check if termination wait time has expired");
        }
        if (rv == 1) {
            break;
        }
        /*  Now that SIGNUM has been sent, switch to sending the null signal
         *    to check for PID existence.
         */
        if (sig != 0) {
            sig = 0;
        }
        _conf_sleep (MUNGE_SIGNAL_CHECK_MSECS);
    }
    return (1);
}


static void
_conf_sleep (int msecs)
{
/*  Sleep for the specified number of milliseconds [msecs].
 */
#if HAVE_CLOCK_NANOSLEEP
    struct timespec check_abstime;
    int             rv;

    rv = clock_get_timespec (&check_abstime, msecs);
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to get check time for termination");
    }
    do {
        rv = clock_nanosleep (CLOCK_REALTIME, TIMER_ABSTIME, &check_abstime,
                NULL);
    } while ((rv < 0) && (errno == EINTR));
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to sleep before checking for termination");
    }
#else  /* !HAVE_CLOCK_NANOSLEEP */
    struct timespec check_reltime;
    int             rv;

    check_reltime.tv_sec = msecs / 1000;
    check_reltime.tv_nsec = (msecs % 1000) * 1000 * 1000;

    do {
        rv = nanosleep (&check_reltime, &check_reltime);
    } while ((rv < 0) && (errno == EINTR));
    if (rv < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to sleep before checking for termination");
    }
#endif /* !HAVE_CLOCK_NANOSLEEP */
}


static void
_conf_set_origin_addr (conf_t conf)
{
/*  Set the origin address to be encoded into credential metadata.
 *  If an origin is explicitly specified, failure to lookup its network address
 *    results in an error which can be overridden.
 *  If an orgin is not specified or the error is overridden, a warning is
 *    logged and the origin address is set to the null address.
 */
    int is_origin_specified;
    int rv = 0;

    assert (conf != NULL);

    memset (&conf->addr, 0, sizeof (conf->addr));
    conf->origin_ifname = NULL;

    is_origin_specified = (conf->origin_name != NULL) ? 1 : 0;

    if (conf->origin_name == NULL) {
        rv = net_get_hostname (&conf->origin_name);
        if (rv < 0) {
            log_msg (LOG_WARNING, "Failed to get name of current host");
        }
    }
    if (conf->origin_name != NULL) {
        errno = 0;
        rv = net_get_hostaddr (conf->origin_name, &conf->addr,
                &conf->origin_ifname);
        if (rv < 0) {
            log_err_or_warn (conf->got_force || !is_origin_specified,
                    "Failed to lookup origin \"%s\"%s%s", conf->origin_name,
                    (errno != 0) ? ": " : "",
                    (errno != 0) ? strerror (errno) : "");
        }
    }
    if (rv != 0) {
        log_msg (LOG_WARNING, "Continuing with origin set to null address");
    }
    return;
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
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to find keyfile \"%s\": %s (%s)",
            keyfile, strerror (errno), "Did you run mungekey?");
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
