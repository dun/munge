/*****************************************************************************
 *  $Id: munge.c,v 1.17 2004/03/02 00:28:48 dun Exp $
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
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <munge.h>
#include "common.h"
#include "read.h"


/***************************************************************************** 
 *  Command-Line Options
 *****************************************************************************/

#if HAVE_GETOPT_H
#  include <getopt.h>
struct option opt_table[] = {
    { "help",         0, NULL, 'h' },
    { "license",      0, NULL, 'L' },
    { "version",      0, NULL, 'V' },
    { "cipher",       1, NULL, 'c' },
    { "list-ciphers", 0, NULL, 'C' },
    { "input",        1, NULL, 'i' },
    { "mac",          1, NULL, 'm' },
    { "list-macs",    0, NULL, 'M' },
    { "no-input",     0, NULL, 'n' },
    { "output",       1, NULL, 'o' },
    { "string",       1, NULL, 's' },
    { "socket",       1, NULL, 'S' },
    { "ttl",          1, NULL, 't' },
    { "zip",          1, NULL, 'z' },
    { "list-zips",    0, NULL, 'Z' },
    {  NULL,          0, NULL,  0  }
};
#endif /* HAVE_GETOPT_H */

const char * const opt_string = "hLVc:Ci:m:Mno:s:S:t:z:Z";


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
void destroy_conf (conf_t conf);
void parse_cmdline (conf_t conf, int argc, char **argv);
void display_help (char *prog);
void display_strings (const char *header, const char **strings);
int str_to_int (const char *s, const char **strings);
void open_files (conf_t conf);
void display_cred (conf_t conf);


/***************************************************************************** 
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t       conf;
    int          rc = 0;
    const char  *p;

    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGPIPE);

    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    if (conf->string)
        rc = read_data_from_string (conf->string, &conf->data, &conf->dlen);
    else if (conf->fn_in)
        rc = read_data_from_file (conf->fp_in, &conf->data, &conf->dlen);
    if (rc < 0) {
        if (errno == ENOMEM)
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to read input");
        else
            log_err (EMUNGE_SNAFU, LOG_ERR, "Read error");
    }
    conf->status = munge_encode (&conf->cred, conf->ctx,
        conf->data, conf->dlen);

    if (conf->status != EMUNGE_SUCCESS) {
        if (!(p = munge_ctx_strerror (conf->ctx)))
            p = munge_strerror (conf->status);
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
    if (!(conf->ctx = munge_ctx_create())) {
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
    if (conf->ctx != NULL) {
        munge_ctx_destroy (conf->ctx);
    }
    if (conf->fp_in != NULL) {
        if (fclose (conf->fp_in) < 0)
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to close infile");
        conf->fp_in = NULL;
    }
    if (conf->fp_out != NULL) {
        if ((fclose (conf->fp_out) < 0) && (errno != EPIPE))
            log_errno (EMUNGE_SNAFU, LOG_ERR, "Unable to close outfile");
        conf->fp_out = NULL;
    }
    if (conf->data != NULL) {
        memset (conf->data, 0, conf->dlen);
        free (conf->data);
        conf->data = NULL;
    }
    if (conf->cred != NULL) {
        memset (conf->cred, 0, conf->clen);
        free (conf->cred);
        conf->cred = NULL;
    }
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
            case 'c':
                if ((i = str_to_int (optarg, munge_cipher_strings)) < 0)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid cipher type \"%s\"", optarg);
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_CIPHER_TYPE, i);
                if (e != EMUNGE_SUCCESS)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set cipher type: %s",
                        munge_ctx_strerror (conf->ctx));
                break;
            case 'C':
                display_strings ("Cipher types", munge_cipher_strings);
                exit (EMUNGE_SUCCESS);
                break;
            case 'i':
                conf->fn_in = optarg;
                conf->string = NULL;
                break;
            case 'm':
                if ((i = str_to_int (optarg, munge_mac_strings)) < 0)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid mesg auth code type \"%s\"", optarg);
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_MAC_TYPE, i);
                if (e != EMUNGE_SUCCESS)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set mesg auth code type: %s",
                        munge_ctx_strerror (conf->ctx));
                break;
            case 'M':
                display_strings ("MAC types", munge_mac_strings);
                exit (EMUNGE_SUCCESS);
                break;
            case 'n':
                conf->fn_in = NULL;
                conf->string = NULL;
                break;
            case 'o':
                conf->fn_out = optarg;
                break;
            case 's':
                conf->fn_in = NULL;
                conf->string = optarg;
                break;
            case 'S':
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_SOCKET, optarg);
                if (e != EMUNGE_SUCCESS)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set munge socket name: %s",
                        munge_ctx_strerror (conf->ctx));
                break;
            case 't':
                i = strtol (optarg, &p, 10);
                if (optarg == p)
                    log_errno (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid time-to-live '%s'", optarg);
                if (i < 0)
                    i = MUNGE_TTL_MAXIMUM;
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_TTL, i);
                if (e != EMUNGE_SUCCESS)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set time-to-live: %s",
                        munge_ctx_strerror (conf->ctx));
                break;
            case 'z':
                if ((i = str_to_int (optarg, munge_zip_strings)) < 0)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Invalid compression type \"%s\"", optarg);
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_ZIP_TYPE, i);
                if (e != EMUNGE_SUCCESS)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set compression type: %s",
                        munge_ctx_strerror (conf->ctx));
                break;
            case 'Z':
                display_strings ("Compression types", munge_zip_strings);
                exit (EMUNGE_SUCCESS);
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

    printf ("\n");

    printf ("  %*s %s\n", w, (got_long ? "-i, --input=FILE" : "-i FILE"),
            "Input payload data from FILE");

    printf ("  %*s %s\n", w, (got_long ? "-n, --no-input" : "-n"),
            "Redirect input from /dev/null");

    printf ("  %*s %s\n", w, (got_long ? "-o, --output=FILE" : "-o FILE"),
            "Output credential to FILE");

    printf ("  %*s %s\n", w, (got_long ? "-s, --string=STRING" : "-s STRING"),
            "Input payload data from STRING");

    printf ("\n");

    printf ("  %*s %s\n", w, (got_long ? "-c, --cipher=STRING" : "-c STRING"),
            "Specify cipher type");

    printf ("  %*s %s\n", w, (got_long ? "-C, --list-ciphers" : "-C"),
            "Print a list of supported ciphers");

    printf ("  %*s %s\n", w, (got_long ? "-m, --mac=STRING" : "-m STRING"),
            "Specify message authentication code type");

    printf ("  %*s %s\n", w, (got_long ? "-M, --list-macs" : "-M"),
            "Print a list of supported MACs");

    printf ("  %*s %s\n", w, (got_long ? "-z, --zip=STRING" : "-z STRING"),
            "Specify compression type");

    printf ("  %*s %s\n", w, (got_long ? "-Z, --list-zips" : "-Z"),
            "Print a list of supported compressions");

    printf ("  %*s %s\n", w, (got_long ? "-S, --socket=STRING" : "-S STRING"),
            "Specify local domain socket");

    printf ("  %*s %s\n", w, (got_long ? "-t, --ttl=INTEGER" : "-t INTEGER"),
            "Specify time-to-live (in seconds; 0=default, -1=max)");

    printf ("\n");
    printf ("By default, data is read from stdin and written to stdout.\n\n");

    return;
}


void
display_strings (const char *header, const char **strings)
{
    const char **pp;
    int i;

    /*  Display each non-empty string in the NULL-terminated list.
     *    Empty strings (ie, "") are invalid.
     */
    printf ("%s:\n\n", header);
    for (pp=strings, i=0; *pp; pp++, i++) {
        if (*pp[0] != '\0')
            printf ("  %s (%d)\n", *pp, i);
    }
    printf ("\n");
    return;
}


int
str_to_int (const char *s, const char **strings)
{
    const char **pp;
    char *p;
    int i;
    int n;

    /*  Check to see if the given string matches a valid string.
     */
    for (pp=strings, i=0; *pp; pp++, i++) {
        if (!strcasecmp (s, *pp))
            return (i);
    }
    /*  Check to see if the given string matches a valid enum.
     */
    if (isdigit (s[0])) {
        n = strtol (s, &p, 10);
        if ((s != p) && (n >= 0) && (n < i) && (strings[n][0] != '\0'))
            return (n);
    }
    return (-1);
}


void
open_files (conf_t conf)
{
    if (conf->fn_in) {
        if (!strcmp (conf->fn_in, "-"))
            conf->fp_in = stdin;
        else if (!(conf->fp_in = fopen (conf->fn_in, "r")))
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to read from \"%s\"", conf->fn_in);
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-"))
            conf->fp_out = stdout;
        else if (!(conf->fp_out = fopen (conf->fn_out, "w")))
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to write to \"%s\"", conf->fn_out);
    }
    return;
}


void
display_cred (conf_t conf)
{
    if (!conf->fp_out)
        return;
    if (fprintf (conf->fp_out, "%s\n", conf->cred) < 0)
        log_errno (EMUNGE_SNAFU, LOG_ERR, "Write error");
    return;
}
