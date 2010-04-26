/*****************************************************************************
 *  $Id$
 *****************************************************************************
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  This file is part of the MUNGE Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://munge.googlecode.com/>.
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
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <munge.h>
#include "common.h"
#include "license.h"
#include "read.h"
#include "version.h"


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

const char * const short_opts = ":hLVns:i:o:c:Cm:Mz:Zu:g:t:S:";

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
    { "restrict-gid", required_argument, NULL, 'g' },
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
void   display_cred (conf_t conf);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t       conf;
    int          rc = 0;
    const char  *p;

    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGPIPE);
    }
    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    if (conf->string) {
        rc = read_data_from_string (conf->string, &conf->data, &conf->dlen);
    }
    else if (conf->fn_in) {
        rc = read_data_from_file (conf->fp_in, &conf->data, &conf->dlen);
    }
    if (rc < 0) {
        if (errno == ENOMEM) {
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to read input");
        }
        else {
            log_err (EMUNGE_SNAFU, LOG_ERR, "Read error");
        }
    }
    conf->status = munge_encode (&conf->cred, conf->ctx,
        conf->data, conf->dlen);

    if (conf->status != EMUNGE_SUCCESS) {
        if (!(p = munge_ctx_strerror (conf->ctx))) {
            p = munge_strerror (conf->status);
        }
        log_err (conf->status, LOG_ERR, "%s", p);
    }
    conf->clen = strlen (conf->cred);

    display_cred (conf);

    destroy_conf (conf);
    exit (EMUNGE_SUCCESS);
}


conf_t
create_conf (void)
{
    conf_t conf;

    if (!(conf = malloc (sizeof (struct conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf");
    }
    if (!(conf->ctx = munge_ctx_create ())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf ctx");
    }
    conf->status = -1;
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
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to close infile");
        }
        conf->fp_in = NULL;
    }
    if (conf->fp_out != NULL) {
        if ((fclose (conf->fp_out) < 0) && (errno != EPIPE)) {
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to close outfile");
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
    char          *prog;
    int            c;
    char          *p;
    munge_err_t    e;
    int            i;
    long int       l;
    struct passwd *pw_ptr;
    struct group  *gr_ptr;

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
                        "Unable to set cipher type: %s",
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
                        "Invalid mac type \"%s\"", optarg);
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_MAC_TYPE, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set mac type: %s",
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
                        "Unable to set compression type: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'Z':
                display_strings ("Compression types", MUNGE_ENUM_ZIP);
                exit (EMUNGE_SUCCESS);
                break;
            case 'u':
                if ((pw_ptr = getpwnam (optarg)) != NULL) {
                    i = pw_ptr->pw_uid;
                }
                else {
                    errno = 0;
                    l = strtol (optarg, &p, 10);
                    if (((errno == ERANGE)
                                && ((l == LONG_MIN) || (l == LONG_MAX)))
                            || (optarg == p) || (*p != '\0')
                            || (l < 0) || (l > INT_MAX)) {
                        log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Unrecognized user \"%s\"", optarg);
                    }
                    i = (int) l;
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_UID_RESTRICTION, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set uid restriction: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'g':
                if ((gr_ptr = getgrnam (optarg)) != NULL) {
                    i = gr_ptr->gr_gid;
                }
                else {
                    errno = 0;
                    l = strtol (optarg, &p, 10);
                    if (((errno == ERANGE)
                                && ((l == LONG_MIN) || (l == LONG_MAX)))
                            || (optarg == p) || (*p != '\0')
                            || (l < 0) || (l > INT_MAX)) {
                        log_err (EMUNGE_SNAFU, LOG_ERR,
                            "Unrecognized group \"%s\"", optarg);
                    }
                    i = (int) l;
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_GID_RESTRICTION, i);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set gid restriction: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 't':
                errno = 0;
                l = strtol (optarg, &p, 10);
                if ((optarg == p) || (*p != '\0')) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid time-to-live '%s'", optarg);
                }
                if (((errno == ERANGE) && (l == LONG_MAX)) || (l > INT_MAX)) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Exceeded maximum time-to-live of %d seconds",
                        INT_MAX);
                }
                if (l < 0) {
                    l = MUNGE_TTL_MAXIMUM;
                }
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_TTL, (int) l);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set time-to-live: %s",
                        munge_ctx_strerror (conf->ctx));
                }
                break;
            case 'S':
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_SOCKET, optarg);
                if (e != EMUNGE_SUCCESS) {
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set munge socket name: %s",
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
                        "Unable to process command-line");
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
                        "Unable to process command-line");
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
            "Display this help");

    printf ("  %*s %s\n", w, "-L, --license",
            "Display license information");

    printf ("  %*s %s\n", w, "-V, --version",
            "Display version information");

    printf ("\n");

    printf ("  %*s %s\n", w, "-n, --no-input",
            "Discard all input for payload");

    printf ("  %*s %s\n", w, "-s, --string=STRING",
            "Input payload from STRING");

    printf ("  %*s %s\n", w, "-i, --input=FILE",
            "Input payload from FILE");

    printf ("  %*s %s\n", w, "-o, --output=FILE",
            "Output credential to FILE");

    printf ("\n");

    printf ("  %*s %s\n", w, "-c, --cipher=STRING",
            "Specify cipher type");

    printf ("  %*s %s\n", w, "-C, --list-ciphers",
            "Display a list of supported ciphers");

    printf ("  %*s %s\n", w, "-m, --mac=STRING",
            "Specify MAC type");

    printf ("  %*s %s\n", w, "-M, --list-macs",
            "Display a list of supported MACs");

    printf ("  %*s %s\n", w, "-z, --zip=STRING",
            "Specify compression type");

    printf ("  %*s %s\n", w, "-Z, --list-zips",
            "Display a list of supported compressions");

    printf ("\n");

    printf ("  %*s %s\n", w, "-u, --restrict-uid=UID",
            "Restrict credential decoding by UID");

    printf ("  %*s %s\n", w, "-g, --restrict-gid=GID",
            "Restrict credential decoding by GID");

    printf ("  %*s %s\n", w, "-t, --ttl=INTEGER",
            "Specify time-to-live (in seconds; 0=dfl -1=max)");

    printf ("  %*s %s\n", w, "-S, --socket=STRING",
            "Specify local domain socket for daemon");

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
                "Unable to read from \"%s\"", conf->fn_in);
        }
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-")) {
            conf->fp_out = stdout;
        }
        else if (!(conf->fp_out = fopen (conf->fn_out, "w"))) {
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to write to \"%s\"", conf->fn_out);
        }
    }
    return;
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
