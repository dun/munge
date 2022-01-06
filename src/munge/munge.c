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

#include <sys/types.h>                  /* include before grp.h for bsd */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <munge.h>
#include "common.h"
#include "license.h"
#include "log.h"
#include "query.h"
#include "read.h"
#include "version.h"
#include "xsignal.h"


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

const char * const short_opts = ":hLVns:i:o:c:Cm:Mz:Zu:U:g:G:t:S:";

#include <getopt.h>
struct option long_opts[] = {
    { "help",         no_argument,       NULL, 'h' },
    { "license",      no_argument,       NULL, 'L' },
    { "version",      no_argument,       NULL, 'V' },
    { "no-input",     no_argument,       NULL, 'n' },
    { "string",       required_argument, NULL, 's' },
    { "input",        required_argument, NULL, 'i' },
    { "output",       required_argument, NULL, 'o' },
    { "cipher",       required_argument, NULL, 'c' },
    { "list-ciphers", no_argument,       NULL, 'C' },
    { "mac",          required_argument, NULL, 'm' },
    { "list-macs",    no_argument,       NULL, 'M' },
    { "zip",          required_argument, NULL, 'z' },
    { "list-zips",    no_argument,       NULL, 'Z' },
    { "restrict-uid", required_argument, NULL, 'u' },
    { "uid",          required_argument, NULL, 'U' },
    { "restrict-gid", required_argument, NULL, 'g' },
    { "gid",          required_argument, NULL, 'G' },
    { "ttl",          required_argument, NULL, 't' },
    { "socket",       required_argument, NULL, 'S' },
    {  NULL,          0,                 NULL,  0  }
};


/*****************************************************************************
 *  Configuration
 *****************************************************************************/

struct conf {
    munge_ctx_t  ctx;                   /* munge context                     */
    munge_err_t  status;                /* error status munging the cred     */
    uid_t        cuid;                  /* credential UID                    */
    gid_t        cgid;                  /* credential GID                    */
    char        *string;                /* input from string instead of file */
    char        *fn_in;                 /* input filename, '-' for stdin     */
    char        *fn_out;                /* output filename, '-' for stdout   */
    FILE        *fp_in;                 /* input file pointer                */
    FILE        *fp_out;                /* output file pointer               */
    int          dlen;                  /* payload data length               */
    void        *data;                  /* payload data                      */
    int          clen;                  /* munged credential length          */
    char        *cred;                  /* munged credential nul-terminated  */
};

typedef struct conf * conf_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t create_conf (void);
void   destroy_conf (conf_t conf);
void   parse_cmdline (conf_t conf, int argc, char **argv);
void   display_help (char *prog);
void   display_strings (const char *header, munge_enum_t type);
void   open_files (conf_t conf);
int    encode_cred (conf_t conf);
void   display_cred (conf_t conf);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t      conf;
    const char *p;

    xsignal_ignore (SIGHUP);
    xsignal_ignore (SIGPIPE);
    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    if (conf->string) {
        read_data_from_string (conf->string, &conf->data, &conf->dlen);
    }
    else if (conf->fn_in) {
        read_data_from_file (conf->fp_in, &conf->data, &conf->dlen);
    }
    if (encode_cred (conf) < 0) {
        if (!(p = munge_ctx_strerror (conf->ctx))) {
            p = munge_strerror (conf->status);
        }
        log_err (conf->status, LOG_ERR, "%s", p);
    }
    conf->clen = strlen (conf->cred);

    display_cred (conf);

    destroy_conf (conf);
    log_close_file ();
    exit (EMUNGE_SUCCESS);
}


conf_t
create_conf (void)
{
    conf_t conf;

    if (!(conf = malloc (sizeof (struct conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to allocate conf");
    }
    if (!(conf->ctx = munge_ctx_create ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Failed to create conf ctx");
    }
    conf->status = -1;
    conf->cuid = geteuid ();
    conf->cgid = getegid ();
    conf->string = NULL;
    conf->fn_in = "-";
    conf->fn_out = "-";
    conf->fp_in = NULL;
    conf->fp_out = NULL;
    conf->dlen = 0;
    conf->data = NULL;
    conf->clen = 0;
    conf->cred = NULL;
    return (conf);
}


void
destroy_conf (conf_t conf)
{
    /*  XXX: Don't free conf's string/fn_in/fn_out
     *       since they point inside argv[].
     */
    if (conf->fp_in != NULL) {
        if (fclose (conf->fp_in) < 0) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close input file");
        }
        conf->fp_in = NULL;
    }
    if (conf->fp_out != NULL) {
        if ((fclose (conf->fp_out) < 0) && (errno != EPIPE)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Failed to close output file");
        }
        conf->fp_out = NULL;
    }
    if (conf->data != NULL) {
        memburn (conf->data, 0, conf->dlen);
        free (conf->data);
        conf->data = NULL;
    }
    if (conf->cred != NULL) {
        memburn (conf->cred, 0, conf->clen);
        free (conf->cred);
        conf->cred = NULL;
    }
    munge_ctx_destroy (conf->ctx);
    free (conf);
    return;
}


void
parse_cmdline (conf_t conf, int argc, char **argv)
{
    char        *prog;
    int          c;
    char        *p;
    munge_err_t  e;
    int          i;
    long int     l;

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
            case 'n':
                conf->fn_in = NULL;
                conf->string = NULL;
                break;
            case 's':
                conf->fn_in = NULL;
                conf->string = optarg;
                break;
            case 'i':
                conf->fn_in = optarg;
                conf->string = NULL;
                break;
            case 'o':
                conf->fn_out = optarg;
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
            case 'U':
                if (query_uid (optarg, (uid_t *) &i) < 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unrecognized user \"%s\"", optarg);
                }
                conf->cuid = (uid_t) i;
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
            case 'G':
                if (query_gid (optarg, (gid_t *) &i) < 0) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unrecognized group \"%s\"", optarg);
                }
                conf->cgid = (gid_t) i;
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

    printf ("\n");

    printf ("  %*s %s\n", w, "-n, --no-input",
            "Discard all input for payload");

    printf ("  %*s %s\n", w, "-s, --string=STR",
            "Input payload from string");

    printf ("  %*s %s\n", w, "-i, --input=PATH",
            "Input payload from file");

    printf ("  %*s %s\n", w, "-o, --output=PATH",
            "Output credential to file");

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

    printf ("  %*s %s\n", w, "-u, --restrict-uid=UID",
            "Restrict credential decoding by user/UID");

    printf ("  %*s %s\n", w, "-U, --uid=UID",
            "Specify credential user/UID");

    printf ("  %*s %s\n", w, "-g, --restrict-gid=GID",
            "Restrict credential decoding by group/GID");

    printf ("  %*s %s\n", w, "-G, --gid=GID",
            "Specify credential group/GID");

    printf ("  %*s %s\n", w, "-t, --ttl=SECS",
            "Specify time-to-live (in seconds; 0=dfl -1=max)");

    printf ("  %*s %s\n", w, "-S, --socket=PATH",
            "Specify local socket for munged");

    printf ("\n");
    printf ("By default, payload read from stdin, "
            "credential written to stdout.\n\n");
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


void
open_files (conf_t conf)
{
    if (conf->fn_in) {
        if (!strcmp (conf->fn_in, "-")) {
            conf->fp_in = stdin;
        }
        else if (!(conf->fp_in = fopen (conf->fn_in, "r"))) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to read from \"%s\"", conf->fn_in);
        }
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-")) {
            conf->fp_out = stdout;
        }
        else if (!(conf->fp_out = fopen (conf->fn_out, "w"))) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Failed to write to \"%s\"", conf->fn_out);
        }
    }
    return;
}


int
encode_cred (conf_t conf)
{
/*  Encodes the credential based on the configuration [conf].
 *  Returns 0 on success, -1 on error.
 */
    uid_t euid;
    gid_t egid;

    euid = geteuid ();
    egid = getegid ();

    if (egid != conf->cgid) {
        if (setegid (conf->cgid) < 0) {
            log_errno (errno, LOG_ERR,
                    "Failed to create credential for GID %u", conf->cgid);
        }
    }
    if (euid != conf->cuid) {
        if (seteuid (conf->cuid) < 0) {
            log_errno (errno, LOG_ERR,
                    "Failed to create credential for UID %u", conf->cuid);
        }
    }
    conf->status = munge_encode (&conf->cred, conf->ctx,
            conf->data, conf->dlen);

    if (euid != conf->cuid) {
        if (seteuid (euid) < 0) {
            log_errno (errno, LOG_ERR,
                    "Failed to restore privileges for UID %u", euid);
        }
    }
    if (egid != conf->cgid) {
        if (setegid (egid) < 0) {
            log_errno (errno, LOG_ERR,
                    "Failed to restore privileges for GID %u", egid);
        }
    }
    return ((conf->status == EMUNGE_SUCCESS) ? 0 : -1);
}


void
display_cred (conf_t conf)
{
    if (!conf->fp_out) {
        return;
    }
    if (fprintf (conf->fp_out, "%s\n", conf->cred) < 0) {
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Write error");
    }
    return;
}
