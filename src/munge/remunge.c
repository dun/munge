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
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <munge.h>
#include "common.h"
#include "license.h"
#include "log.h"
#include "query.h"
#include "version.h"
#include "xsignal.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define DEF_DO_DECODE           0
#define DEF_NUM_THREADS         1
#define DEF_PAYLOAD_LENGTH      0
#define DEF_WARNING_TIME        5
#define MIN_DURATION            0.5


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

const char * const short_opts = ":hLVqc:Cm:Mz:Zedl:u:g:t:S:D:N:T:W:";

#include <getopt.h>
struct option long_opts[] = {
    { "help",         no_argument,       NULL, 'h' },
    { "license",      no_argument,       NULL, 'L' },
    { "version",      no_argument,       NULL, 'V' },
    { "quiet",        no_argument,       NULL, 'q' },
    { "cipher",       required_argument, NULL, 'c' },
    { "list-ciphers", no_argument,       NULL, 'C' },
    { "mac",          required_argument, NULL, 'm' },
    { "list-macs",    no_argument,       NULL, 'M' },
    { "zip",          required_argument, NULL, 'z' },
    { "list-zips",    no_argument,       NULL, 'Z' },
    { "encode",       no_argument,       NULL, 'e' },
    { "decode",       no_argument,       NULL, 'd' },
    { "length",       required_argument, NULL, 'l' },
    { "restrict-uid", required_argument, NULL, 'u' },
    { "restrict-gid", required_argument, NULL, 'g' },
    { "ttl",          required_argument, NULL, 't' },
    { "socket",       required_argument, NULL, 'S' },
    { "duration",     required_argument, NULL, 'D' },
    { "num-creds",    required_argument, NULL, 'N' },
    { "num-threads",  required_argument, NULL, 'T' },
    { "warn-time",    required_argument, NULL, 'W' },
    {  NULL,          0,                 NULL,  0  }
};


/*****************************************************************************
 *  Data Types
 *****************************************************************************/

/*  LOCKING PROTOCOL:
 *    The mutex must be locked when accessing the following fields:
 *      num_creds_done, num_encode_errs, num_decode_errs.
 *    The remaining fields are either not shared between threads or
 *      are constant while processing credentials.
 */
struct conf {
    munge_ctx_t     ctx;                /* munge context                     */
    int             do_decode;          /* true to decode/validate all creds */
    char           *payload;            /* payload to be encoded into cred   */
    int             num_payload;        /* number of bytes for cred payload  */
    int             max_threads;        /* max number of threads available   */
    int             num_threads;        /* number of threads to spawn        */
    int             num_running;        /* number of threads now running     */
    int             num_seconds;        /* number of seconds to run          */
    unsigned long   num_creds;          /* number of credentials to process  */
    int             warn_time;          /* number of seconds to allow for op */
    struct timeval  t_main_start;       /* time when cred processing started */
    struct timeval  t_main_stop;        /* time when cred processing stopped */
    pthread_t      *tids;               /* ptr to array of thread IDs        */
    pthread_mutex_t mutex;              /* mutex for accessing shared data   */
    pthread_cond_t  cond_done;          /* cond for when last thread is done */

    struct {                            /* thread-modified data; mutex req'd */
      unsigned long num_creds_done;     /*   number of credentials processed */
      unsigned long num_encode_errs;    /*   number of errors encoding creds */
      unsigned long num_decode_errs;    /*   number of errors decoding creds */
    }               shared;
};
typedef struct conf * conf_t;

struct thread_data {
    conf_t          conf;               /* reference to global configuration */
    munge_ctx_t     ectx;               /* local munge context for encodes   */
    munge_ctx_t     dctx;               /* local munge context for decodes   */
};
typedef struct thread_data * tdata_t;

typedef void * (*thread_f) (void *);
typedef void   (*thread_cleanup_f) (void *);


/*****************************************************************************
 *  Global Variables
 *****************************************************************************/

int g_got_quiet = 0;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t  create_conf (void);
void    destroy_conf (conf_t conf);
tdata_t create_tdata (conf_t conf);
void    destroy_tdata (tdata_t tdata);
void    parse_cmdline (conf_t conf, int argc, char **argv);
void    display_help (char *prog);
void    display_strings (const char *header, munge_enum_t type);
int     get_si_multiple (char c);
int     get_time_multiple (char c);
void    start_threads (conf_t conf);
void    process_creds (conf_t conf);
void    stop_threads (conf_t conf);
void *  remunge (conf_t conf);
void    remunge_cleanup (tdata_t tdata);
void    output_msg (const char *format, ...);


/*****************************************************************************
 *  Macros
 *****************************************************************************/

#define GET_TIMEVAL(TV)                                                       \
    do {                                                                      \
        if (gettimeofday ((&TV), NULL) == -1) {                               \
            log_errno (EMUNGE_SNAFU, LOG_ERR,                                 \
                "Failed to query current time");                              \
        }                                                                     \
    } while (0)

#define DIFF_TIMEVAL(TV1, TV0)                                                \
    ( ((TV1).tv_sec  - (TV0).tv_sec ) +                                       \
     (((TV1).tv_usec - (TV0).tv_usec) / 1e6) )


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t conf;

    xsignal_ignore (SIGHUP);
    xsignal_ignore (SIGPIPE);

    /*  Close stdin since it is not used.
     */
    if (close (STDIN_FILENO) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close standard input");
    }
    /*  Set stdout to be line buffered.
     */
    if (setvbuf (stdout, NULL, _IOLBF, 0) < 0) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to line-buffer standard output");
    }
    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);

    start_threads (conf);
    process_creds (conf);
    stop_threads (conf);

    destroy_conf (conf);
    log_close_file ();
    exit (EMUNGE_SUCCESS);
}


conf_t
create_conf (void)
{
/*  Creates and returns the default configuration.
 *  Returns a valid ptr or dies trying.
 */
    conf_t conf;
    int    n;

    if (!(conf = malloc (sizeof (*conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate conf");
    }
    if (!(conf->ctx = munge_ctx_create ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to create conf ctx");
    }
    if ((errno = pthread_mutex_init (&conf->mutex, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to init mutex");
    }
    if ((errno = pthread_cond_init (&conf->cond_done, NULL)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to init condition");
    }
    conf->do_decode = DEF_DO_DECODE;
    conf->payload = NULL;
    conf->num_payload = DEF_PAYLOAD_LENGTH;;
    conf->num_threads = DEF_NUM_THREADS;
    conf->num_running = 0;
    conf->num_seconds = 0;
    conf->num_creds = 0;
    conf->shared.num_creds_done = 0;
    conf->shared.num_encode_errs = 0;
    conf->shared.num_decode_errs = 0;
    conf->warn_time = DEF_WARNING_TIME;
    conf->tids = NULL;
    /*
     *  Compute the maximum number of threads available for the process.
     *    Each thread requires an open file descriptor to communicate with
     *    the local munge daemon.  Reserve 2 fds for stdout and stderr.
     *    And reserve 2 fds in case LinuxThreads is being used.
     */
    errno = 0;
    if (((n = sysconf (_SC_OPEN_MAX)) == -1) && (errno != 0)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to determine maximum number of open files");
    }
    if ((conf->max_threads = n - 2 - 2) < 1) {
        log_err (EMUNGE_SNAFU, LOG_ERR,
            "Failed to compute maximum number of threads");
    }
    return (conf);
}


void
destroy_conf (conf_t conf)
{
/*  Destroys the configuration [conf].
 */
    assert (conf != NULL);

    if (conf->payload) {
        assert (conf->num_payload > 0);
        free (conf->payload);
    }
    if ((errno = pthread_cond_destroy (&conf->cond_done)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to destroy condition");
    }
    if ((errno = pthread_mutex_destroy (&conf->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to destroy mutex");
    }
    munge_ctx_destroy (conf->ctx);
    free (conf->tids);
    free (conf);
    return;
}


tdata_t
create_tdata (conf_t conf)
{
/*  Create thread-specific data referencing back to the global config [conf].
 *    This struct is required since remunge_cleanup() needs access to both
 *    the global conf mutex and the local munge context.
 *  Returns a valid ptr or dies trying.
 */
    tdata_t tdata;

    assert (conf != NULL);

    if (!(tdata = malloc (sizeof (*tdata)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR,
            "Failed to allocate thread data");
    }
    tdata->conf = conf;
    /*
     *  The munge ctx in the global conf is copied since each thread needs
     *    access to its own local ctx for thread-safety.
     *  A separate ctx is used for both encoding and decoding since a
     *    decode error could place the ctx in an invalid state for encoding.
     *  The decode ctx is copied from the global conf instead of creating
     *    a new one from scratch in order to preserve the location of the
     *    munge socket (which may have been set in the conf).
     */
    if (!(tdata->ectx = munge_ctx_copy (conf->ctx))) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to copy munge encode context");
    }
    if ((conf->do_decode) && !(tdata->dctx = munge_ctx_copy (conf->ctx))) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Failed to copy munge decode context");
    }
    return (tdata);
}


void
destroy_tdata (tdata_t tdata)
{
/*  Destroy the thread-specific data [tdata].
 */
    assert (tdata != NULL);

    if (tdata->conf->do_decode) {
        munge_ctx_destroy (tdata->dctx);
    }
    munge_ctx_destroy (tdata->ectx);
    free (tdata);
    return;
}


void
parse_cmdline (conf_t conf, int argc, char **argv)
{
/*  Parses the command-line, altering the configuration [conf] as specified.
 */
    char          *prog;
    int            c;
    char          *p;
    int            i;
    long int       l;
    unsigned long  u;
    int            multiplier;
    munge_err_t    e;

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
            case 'q':
                g_got_quiet = 1;
                break;
            case 'c':
                i = munge_enum_str_to_int (MUNGE_ENUM_CIPHER, optarg);
                if ((i < 0) || !munge_enum_is_valid (MUNGE_ENUM_CIPHER, i)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid cipher type \"%s\"", optarg);
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_CIPHER_TYPE, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set cipher type: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'C':
                display_strings ("Cipher types", MUNGE_ENUM_CIPHER);
                exit (EMUNGE_SUCCESS);
                break;
            case 'm':
                i = munge_enum_str_to_int (MUNGE_ENUM_MAC, optarg);
                if ((i < 0) || !munge_enum_is_valid (MUNGE_ENUM_MAC, i)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid MAC type \"%s\"", optarg);
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_MAC_TYPE, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set MAC type: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'M':
                display_strings ("MAC types", MUNGE_ENUM_MAC);
                exit (EMUNGE_SUCCESS);
                break;
            case 'z':
                i = munge_enum_str_to_int (MUNGE_ENUM_ZIP, optarg);
                if ((i < 0) || !munge_enum_is_valid (MUNGE_ENUM_ZIP, i)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid compression type \"%s\"", optarg);
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_ZIP_TYPE, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set compression type: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'Z':
                display_strings ("Compression types", MUNGE_ENUM_ZIP);
                exit (EMUNGE_SUCCESS);
                break;
            case 'e':
                conf->do_decode = 0;
                break;
            case 'd':
                conf->do_decode = 1;
                break;
            case 'l':
                errno = 0;
                l = strtol (optarg, &p, 10);
                if ((optarg == p) || ((*p != '\0') && (*(p+1) != '\0'))
                        || (l < 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid number of bytes '%s'", optarg);
                }
                if (((errno == ERANGE) && (l == LONG_MAX)) || (l > INT_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum number of %d bytes", INT_MAX);
                }
                if (!(multiplier = get_si_multiple (*p))) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid number specifier '%c'", *p);
                }
                if (l > (INT_MAX / multiplier)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum number of %d bytes", INT_MAX);
                }
                conf->num_payload = (int) (l * multiplier);
                break;
            case 'u':
                if (query_uid (optarg, (uid_t *) &i) < 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unrecognized user \"%s\"", optarg);
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_UID_RESTRICTION, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set UID restriction: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'g':
                if (query_gid (optarg, (gid_t *) &i) < 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unrecognized group \"%s\"", optarg);
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_GID_RESTRICTION, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set GID restriction: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 't':
                errno = 0;
                l = strtol (optarg, &p, 10);
                if ((optarg == p) || (*p != '\0') || (l < -1)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid time-to-live '%s'", optarg);
                }
                if ((errno == ERANGE) && (l == LONG_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Overflowed maximum time-to-live of %ld seconds",
                        LONG_MAX);
                }
                if (l > UINT_MAX) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum time-to-live of %u seconds",
                        UINT_MAX);
                }
                if (l == -1) {
                    l = MUNGE_TTL_MAXIMUM;
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_TTL, (int) l);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set time-to-live: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'S':
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_SOCKET, optarg);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Failed to set munge socket name: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'D':
                errno = 0;
                l = strtol (optarg, &p, 10);
                if ((optarg == p) || ((*p != '\0') && (*(p+1) != '\0'))
                        || (l <= 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid duration '%s'", optarg);
                }
                if (((errno == ERANGE) && (l == LONG_MAX)) || (l > INT_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum duration of %d seconds", INT_MAX);
                }
                if (!(multiplier = get_time_multiple (*p))) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid duration specifier '%c'", *p);
                }
                if (l > (INT_MAX / multiplier)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum duration of %d seconds", INT_MAX);
                }
                conf->num_seconds = (int) (l * multiplier);
                break;
            case 'N':
                errno = 0;
                u = strtoul (optarg, &p, 10);
                if ((optarg == p) || ((*p != '\0') && (*(p+1) != '\0'))
                        || (u == 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid number of credentials '%s'", optarg);
                }
                if ((errno == ERANGE) && (u == ULONG_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum number of %lu credentials",
                        ULONG_MAX);
                }
                if (!(multiplier = get_si_multiple (*p))) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid number specifier '%c'", *p);
                }
                if (u > (ULONG_MAX / multiplier)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum number of %lu credentials",
                        ULONG_MAX);
                }
                conf->num_creds = u * multiplier;
                break;
            case 'T':
                errno = 0;
                l = strtol (optarg, &p, 10);
                if ((optarg == p) || (*p != '\0') || (l <= 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid number of threads '%s'", optarg);
                }
                if (((errno == ERANGE) && (l == LONG_MAX)) || (l > INT_MAX)
                        || (l > conf->max_threads)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum number of %d thread%s",
                        conf->max_threads,
                        (conf->max_threads == 1) ? "" : "s");
                }
                conf->num_threads = (int) l;
                break;
            case 'W':
                errno = 0;
                l = strtol (optarg, &p, 10);
                if ((optarg == p) || (*p != '\0') || (l <= 0)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid number of seconds '%s'", optarg);
                }
                if (((errno == ERANGE) && (l == LONG_MAX)) || (l > INT_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum number of %d seconds", INT_MAX);
                }
                conf->warn_time = (int) l;
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
    /*  Create arbitrary payload of the specified length.
     */
    if (conf->num_payload > 0) {
        if (!(conf->payload = malloc (conf->num_payload + 1))) {
            log_err (EMUNGE_NO_MEMORY, LOG_ERR,
                "Failed to allocate credential payload of %d byte%s",
                conf->num_payload, (conf->num_payload == 1 ? "" : "s"));
        }
        for (i = 0, c = 'A'; i < conf->num_payload; i++) {
            if ((conf->payload[i] = c++) == 'Z') {
                c = 'A';
            }
        }
        conf->payload[conf->num_payload] = '\0';
    }
    return;
}


void
display_help (char *prog)
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

    printf ("  %*s %s\n", w, "-q, --quiet",
            "Display only the creds/sec numeric result");

    printf ("\n");

    printf ("  %*s %s\n", w, "-c, --cipher=STR",
            "Specify cipher type");

    printf ("  %*s %s\n", w, "-C, --list-ciphers",
            "Display a list of supported ciphers");

    printf ("  %*s %s\n", w, "-m, --mac=STR",
            "Specify MAC type");

    printf ("  %*s %s\n", w, "-M, --list-macs",
            "Display a list of supported MACs");

    printf ("  %*s %s\n", w, "-z, --zip=STR",
            "Specify compression type");

    printf ("  %*s %s\n", w, "-Z, --list-zips",
            "Display a list of supported compressions");

    printf ("\n");

    printf ("  %*s %s\n", w, "-e, --encode",
            "Encode (but do not decode) each credential");

    printf ("  %*s %s\n", w, "-d, --decode",
            "Encode and decode each credential");

    printf ("  %*s %s\n", w, "-l, --length=BYTES",
            "Specify payload length (in bytes)");

    printf ("  %*s %s\n", w, "-u, --restrict-uid=UID",
            "Restrict credential decoding by user/UID");

    printf ("  %*s %s\n", w, "-g, --restrict-gid=GID",
            "Restrict credential decoding by group/GID");

    printf ("  %*s %s\n", w, "-t, --ttl=SECS",
            "Specify time-to-live (in seconds; 0=dfl -1=max)");

    printf ("  %*s %s\n", w, "-S, --socket=PATH",
            "Specify local socket for munged");

    printf ("\n");

    printf ("  %*s %s\n", w, "-D, --duration=SECS",
            "Specify test duration (in seconds; -1=max)");

    printf ("  %*s %s\n", w, "-N, --num-creds=INT",
            "Specify number of credentials to generate");

    printf ("  %*s %s\n", w, "-T, --num-threads=INT",
            "Specify number of threads to spawn");

    printf ("  %*s %s\n", w, "-W, --warn-time=SECS",
            "Specify max seconds for munge op before warning");

    printf ("\n");
    return;
}


void
display_strings (const char *header, munge_enum_t type)
{
    int         i;
    const char *p;

    if (header) {
        printf ("%s:\n\n", header);
    }
    for (i = 0; (p = munge_enum_int_to_str (type, i)); i++) {
        if (munge_enum_is_valid (type, i)) {
            printf ("  %s (%d)\n", p, i);
        }
    }
    printf ("\n");
    return;
}


int
get_si_multiple (char c)
{
/*  Converts the SI-suffix [c] into an equivalent multiplier.
 *  Returns the multiple, or 0 if invalid.
 */
    int multiple;

    switch (c) {
        case '\0':                      /* bytes */
            multiple = 1;
            break;
        case 'k':                       /* kilobytes */
            multiple = 1e3;
            break;
        case 'K':                       /* kibibytes */
            multiple = 1 << 10;
            break;
        case 'm':                       /* megabytes */
            multiple = 1e6;
            break;
        case 'M':                       /* mebibytes */
            multiple = 1 << 20;
            break;
        case 'g':                       /* gigabytes */
            multiple = 1e9;
            break;
        case 'G':                       /* gibibytes */
            multiple = 1 << 30;
            break;
        default:
            multiple = 0;
            break;
    }
    return (multiple);
}


int
get_time_multiple (char c)
{
/*  Converts the time suffix [c] into a multiplier for computing
 *    the number of seconds.
 *  Returns the multiple, or 0 if invalid.
 */
    int multiple;

    switch (c) {
        case '\0':
        case 's':
        case 'S':
            multiple = 1;
            break;
        case 'm':
        case 'M':
            multiple = 60;
            break;
        case 'h':
        case 'H':
            multiple = 60 * 60;
            break;
        case 'd':
        case 'D':
            multiple = 60 * 60 * 24;
            break;
        default:
            multiple = 0;
            break;
    }
    return (multiple);
}


void
start_threads (conf_t conf)
{
/*  Start the number of threads specified by [conf] for processing credentials.
 */
    pthread_attr_t tattr;
    size_t         stacksize = 256 * 1024;
    int            i;

    if (!(conf->tids = malloc (sizeof (*conf->tids) * conf->num_threads))) {
        log_err (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate tid array");
    }
    if ((errno = pthread_attr_init (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to init thread attribute");
    }
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    if ((errno = pthread_attr_setstacksize (&tattr, stacksize)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to set thread stacksize");
    }
#endif /* _POSIX_THREAD_ATTR_STACKSIZE */
    /*
     *  Lock mutex to prevent threads from starting until all are created.
     *    After the timer has been started, the mutex will be unlocked via
     *    pthread_cond_timedwait().
     */
    if ((errno = pthread_mutex_lock (&conf->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock mutex");
    }
    /*  The purpose of the num_running count is for signaling the main thread
     *    when the last worker thread has exited in order to interrupt the
     *    pthread_cond_timedwait().  The reason num_running is set to
     *    num_threads here instead of incrementing it at the start of each
     *    thread is to prevent this condition from being signaled prematurely.
     *    This could happen if all credentials are processed by just a few
     *    threads before all threads have been scheduled to run; consequently,
     *    num_running would bounce to 0 before all threads have finished while
     *    the remaining threads would have no credentials left to process.
     */
    assert (conf->num_threads > 0);
    conf->num_running = conf->num_threads;

    output_msg ("Spawning %d thread%s for %s",
        conf->num_threads, ((conf->num_threads == 1) ? "" : "s"),
        (conf->do_decode ? "encoding/decoding" : "encoding"));

    for (i = 0; i < conf->num_threads; i++) {
        if ((errno = pthread_create
                    (&conf->tids[i], &tattr, (thread_f) remunge, conf)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to create thread #%d", i+1);
        }
    }
    if ((errno = pthread_attr_destroy (&tattr)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR,
            "Failed to destroy thread attribute");
    }
    return;
}


void
process_creds (conf_t conf)
{
/*  Process credentials according to the configuration [conf].
 *  Processing continues for the specified duration or until the
 *    credential count is reached, whichever comes first.
 */
    int             n_secs;
    unsigned long   n_creds;
    struct timespec to;

    /*  Start the main timer before the timeout is computed below.
     */
    GET_TIMEVAL (conf->t_main_start);
    /*
     *  The default is to process credentials for 1 second.
     */
    if (!conf->num_creds && !conf->num_seconds) {
        conf->num_seconds = 1;
    }
    /*  Save configuration values before they are further modified.
     */
    n_secs = conf->num_seconds;
    n_creds = conf->num_creds;
    /*
     *  If a duration is not specified (either explicitly or implicitly),
     *    set the timeout to the maximum value so pthread_cond_timedwait()
     *    can still be used.
     */
    if (conf->num_seconds) {
        to.tv_sec = conf->t_main_start.tv_sec + conf->num_seconds;
        if (to.tv_sec < conf->t_main_start.tv_sec) {
            to.tv_sec = (sizeof (to.tv_sec) == 4) ? INT_MAX : LONG_MAX;
        }
        to.tv_nsec = conf->t_main_start.tv_usec * 1e3;
    }
    else {
        to.tv_sec = (sizeof (to.tv_sec) == 4) ? INT_MAX : LONG_MAX;
        to.tv_nsec = 0;
    }
    /*  Recompute the number of seconds in case the specified duration
     *    exceeded the maximum timeout.
     */
    conf->num_seconds = to.tv_sec - conf->t_main_start.tv_sec;
    /*
     *  If a credential count was not specified, set the limit at the maximum.
     */
    if (!conf->num_creds) {
        conf->num_creds = ULONG_MAX;
    }
    /*  Output processing start message.
     */
    if (n_creds && !n_secs) {
        output_msg ("Processing %lu credential%s",
            conf->num_creds,   ((conf->num_creds   == 1) ? "" : "s"));
    }
    else if (n_secs && !n_creds) {
        output_msg ("Processing credentials for %d second%s",
            conf->num_seconds, ((conf->num_seconds == 1) ? "" : "s"));
    }
    else {
        output_msg ("Processing %lu credential%s for up to %d second%s",
            conf->num_creds,   ((conf->num_creds   == 1) ? "" : "s"),
            conf->num_seconds, ((conf->num_seconds == 1) ? "" : "s"));
    }
    /*  Start processing credentials.
     */
    while (conf->num_running > 0) {

        errno = pthread_cond_timedwait (&conf->cond_done, &conf->mutex, &to);

        if (!errno || (errno == ETIMEDOUT)) {
            break;
        }
        else if (errno == EINTR) {
            continue;
        }
        else {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to wait on condition");
        }
    }
    return;
}


void
stop_threads (conf_t conf)
{
/*  Stop the threads from processing further credentials.  Output the results.
 */
    int           i;
    unsigned long n;
    double        delta;
    double        rate;

    /*  The mutex must be unlocked here in order to let the threads clean up
     *    (via remunge_cleanup()) once they are canceled/finished.
     */
    if ((errno = pthread_mutex_unlock (&conf->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock mutex");
    }
    for (i = 0; i < conf->num_threads; i++) {
        errno = pthread_cancel (conf->tids[i]);
        if ((errno != 0) && (errno != ESRCH)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to cancel thread #%d", i+1);
        }
    }
    for (i = 0; i < conf->num_threads; i++) {
        if ((errno = pthread_join (conf->tids[i], NULL)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to join thread #%d", i+1);
        }
        conf->tids[i] = 0;
    }
    /*  Stop the main timer now that all credential processing has stopped.
     */
    GET_TIMEVAL (conf->t_main_stop);
    delta = DIFF_TIMEVAL (conf->t_main_stop, conf->t_main_start);
    /*
     *  Output processing stop message and results.
     */
    if (conf->shared.num_encode_errs && conf->shared.num_decode_errs) {
        output_msg ("Generated %lu encoding error%s and %lu decoding error%s",
            conf->shared.num_encode_errs,
            ((conf->shared.num_encode_errs == 1) ? "" : "s"),
            conf->shared.num_decode_errs,
            ((conf->shared.num_decode_errs == 1) ? "" : "s"));
    }
    else if (conf->shared.num_encode_errs) {
        output_msg ("Generated %lu encoding error%s",
            conf->shared.num_encode_errs,
            ((conf->shared.num_encode_errs == 1) ? "" : "s"));
    }
    else if (conf->shared.num_decode_errs) {
        output_msg ("Generated %lu decoding error%s",
            conf->shared.num_decode_errs,
            ((conf->shared.num_decode_errs == 1) ? "" : "s"));
    }
    /*  Subtract the errors from the number of credentials processed.
     */
    n = conf->shared.num_creds_done
        - conf->shared.num_encode_errs
        - conf->shared.num_decode_errs;
    rate = n / delta;
    output_msg ("Processed %lu credential%s in %0.3fs (%0.0f creds/sec)",
        n, ((n == 1) ? "" : "s"), delta, rate);
    if (g_got_quiet) {
        printf ("%0.0f\n", rate);
    }
    /*  Check for minimum duration time interval.
     */
    if (delta < MIN_DURATION) {
        printf ("\nWARNING: Results based on such a short time interval "
                "are of low accuracy\n\n");
    }
    return;
}


void *
remunge (conf_t conf)
{
/*  Worker thread responsible for encoding/decoding/validating credentials.
 */
    tdata_t         tdata;
    int             cancel_state;
    unsigned long   n;
    unsigned long   got_encode_err;
    unsigned long   got_decode_err;
    struct timeval  t_start;
    struct timeval  t_stop;
    double          delta;
    munge_err_t     e;
    char           *cred;
    void           *data;
    int             dlen;
    uid_t           uid;
    gid_t           gid;

    tdata = create_tdata (conf);

    pthread_cleanup_push ((thread_cleanup_f) remunge_cleanup, tdata);

    if ((errno = pthread_mutex_lock (&conf->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock mutex");
    }
    while (conf->num_creds - conf->shared.num_creds_done > 0) {

        pthread_testcancel ();

        if ((errno = pthread_setcancelstate
                    (PTHREAD_CANCEL_DISABLE, &cancel_state)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to disable thread cancellation");
        }
        n = ++conf->shared.num_creds_done;

        if ((errno = pthread_mutex_unlock (&conf->mutex)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock mutex");
        }
        got_encode_err = 0;
        got_decode_err = 0;
        data = NULL;

        GET_TIMEVAL (t_start);
        e = munge_encode(&cred, tdata->ectx, conf->payload, conf->num_payload);
        GET_TIMEVAL (t_stop);

        delta = DIFF_TIMEVAL (t_stop, t_start);
        if (delta > conf->warn_time) {
            output_msg ("Credential #%lu encoding took %0.3f seconds",
                n, delta);
        }
        if (e != EMUNGE_SUCCESS) {
            output_msg ("Credential #%lu encoding failed: %s (err=%d)",
                n, munge_ctx_strerror (tdata->ectx), e);
            ++got_encode_err;
        }
        else if (conf->do_decode) {

            GET_TIMEVAL (t_start);
            e = munge_decode (cred, tdata->dctx, &data, &dlen, &uid, &gid);
            GET_TIMEVAL (t_stop);

            delta = DIFF_TIMEVAL (t_stop, t_start);
            if (delta > conf->warn_time) {
                output_msg ("Credential #%lu decoding took %0.3f seconds",
                    n, delta);
            }
            if (e != EMUNGE_SUCCESS) {
                output_msg ("Credential #%lu decoding failed: %s (err=%d)",
                    n, munge_ctx_strerror (tdata->dctx), e);
                ++got_decode_err;
            }

/*  FIXME:
 *    The following block does some validating of the decoded credential.
 *    It should have a cmdline option to enable this validation check.
 *    The decode ctx should also be checked against the encode ctx.
 *    This becomes slightly more difficult in that it must also take
 *    into account the default field settings.
 *
 *    This block should be moved into a separate function (or more).
 *    The [cred], [data], [dlen], [uid], and [gid] vars could be placed
 *    into the tdata struct to facilitate parameter passing.
 */
#if 0
            else if (conf->do_validate) {
                if (getuid () != uid) {
                output_msg (
                    "Credential #%lu UID %d does not match process UID %d",
                    n, uid, getuid ());
                }
                if (getgid () != gid) {
                    output_msg (
                        "Credential #%lu GID %d does not match process GID %d",
                        n, gid, getgid ());
                }
                if (conf->num_payload != dlen) {
                    output_msg (
                        "Credential #%lu payload length mismatch (%d/%d)",
                        n, conf->num_payload, dlen);
                }
                else if (data && memcmp (conf->payload, data, dlen) != 0) {
                    output_msg ("Credential #%lu payload mismatch", n);
                }
            }
#endif /* 0 */

            /*  The 'data' parm can still be set on certain munge errors.
             */
            if (data != NULL) {
                free (data);
            }
        }
        if (cred != NULL) {
            free (cred);
        }
        if ((errno = pthread_setcancelstate
                    (cancel_state, &cancel_state)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to enable thread cancellation");
        }
        if ((errno = pthread_mutex_lock (&conf->mutex)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to lock mutex");
        }
        conf->shared.num_encode_errs += got_encode_err;
        conf->shared.num_decode_errs += got_decode_err;
    }
    pthread_cleanup_pop (1);
    return (NULL);
}


void
remunge_cleanup (tdata_t tdata)
{
/*  Signal the main thread when the last worker thread is exiting.
 *  Clean up resources held by the thread.
 */
    if (--tdata->conf->num_running == 0) {
        if ((errno = pthread_cond_signal (&tdata->conf->cond_done)) != 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to signal condition");
        }
    }
    if ((errno = pthread_mutex_unlock (&tdata->conf->mutex)) != 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to unlock mutex");
    }
    destroy_tdata (tdata);
    return;
}


void
output_msg (const char *format, ...)
{
/*  Outputs the current time followed by the [format] string
 *    to stdout in a thread-safe manner.
 */
    time_t     t;
    struct tm  tm;
    struct tm *tm_ptr;
    char       buf[256];
    char      *p = buf;
    int        len = sizeof (buf);
    int        n;
    va_list    vargs;

    if (g_got_quiet) {
        return;
    }
    if (!format) {
        return;
    }
    if (time (&t) == ((time_t) -1)) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to query current time");
    }
#if HAVE_LOCALTIME_R
    tm_ptr = localtime_r (&t, &tm);
#else  /* !HAVE_LOCALTIME_R */
    tm_ptr = localtime (&t);
#endif /* !HAVE_LOCALTIME_R */

    if (tm_ptr != NULL) {
        n = strftime (p, len, "%Y-%m-%d %H:%M:%S ", tm_ptr);
        if ((n <= 0) || (n >= len)) {
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Exceeded buffer while writing timestamp");
        }
        p += n;
        len -= n;
    }
    va_start (vargs, format);
    n = vsnprintf (p, len, format, vargs);
    va_end (vargs);

    if ((n < 0) || (n >= len)) {
        buf[sizeof (buf) - 2] = '+';
        buf[sizeof (buf) - 1] = '\0';   /* technically redundant */
    }
    printf ("%s\n", buf);
    return;
}
