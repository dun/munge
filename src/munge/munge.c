/*****************************************************************************
 *  $Id: munge.c,v 1.2 2003/02/13 18:19:34 dun Exp $
 *****************************************************************************
 *  This file is part of the Munge Uid 'N' Gid Emporium (MUNGE).
 *  For details, see <http://www.llnl.gov/linux/munge/>.
 *  UCRL-CODE-2003-???.
 *
 *  Copyright (C) 2003 The Regents of the University of California.
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


#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <munge.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "read.h"


/***************************************************************************** 
 *  Options
 *****************************************************************************/

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
struct option opt_table[] = {
    { "help",     0, NULL, 'h' },
    { "license",  0, NULL, 'L' },
    { "version",  0, NULL, 'V' },
    { "input",    1, NULL, 'i' },
    { "no-input", 0, NULL, 'n' },
    { "output",   1, NULL, 'o' },
    { "string",   1, NULL, 's' },
    {  NULL,      0, NULL,  0  }
};
#endif /* HAVE_GETOPT_H */

const char * const opt_string = "hLVi:no:s:";


/***************************************************************************** 
 *  Configuration
 *****************************************************************************/

struct conf {
    char *string;                       /* input from string instead of file */
    char *fn_in;                        /* input filename, '-' for stdin     */
    char *fn_out;                       /* output filename, '-' for stdout   */
    FILE *fp_in;                        /* input file pointer                */
    FILE *fp_out;                       /* output file pointer               */
    int   dlen;                         /* payload data length               */
    void *data;                         /* payload data                      */
    int   clen;                         /* munged credential length          */
    char *cred;                         /* munged credential nul-terminated  */
};

typedef struct conf * conf_t;


/***************************************************************************** 
 *  Prototypes
 *****************************************************************************/

conf_t create_conf (void);
void destroy_conf (conf_t conf);
void parse_cmdline (conf_t conf, int argc, char **argv);
void display_help (char *prog);
void open_files (conf_t conf);
void display_cred (conf_t conf);


/***************************************************************************** 
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t      conf;
    int         rc = 0;
    munge_err_t e;

    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    if (conf->string)
        rc = read_data_from_string (conf->string, &conf->data, &conf->dlen);
    else if (conf->fn_in)
        rc = read_data_from_file (conf->fp_in, &conf->data, &conf->dlen);
    if (rc < 0)
        log_err (EMUNGE_SNAFU, "%s",
            (errno == ENOMEM) ? strerror (errno) : "Read error");

    e = munge_encode (&conf->cred, NULL, conf->data, conf->dlen);
    if (e != EMUNGE_SUCCESS)
        log_err (e, "%s", munge_strerror (e));
    conf->clen = strlen (conf->cred);

    display_cred (conf);

    destroy_conf (conf);
    exit (EMUNGE_SUCCESS);
}


conf_t
create_conf (void)
{
    conf_t conf;

    if (!(conf = malloc (sizeof (*conf))))
        log_err (EMUNGE_SNAFU, "%s", strerror (errno));

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
        if (fclose (conf->fp_in) < 0)
            log_err (EMUNGE_SNAFU, "Unable to close infile: %s",
                strerror (errno));
        conf->fp_in = NULL;
    }
    if (conf->fp_out != NULL) {
        if (fclose (conf->fp_out) < 0)
            log_err (EMUNGE_SNAFU, "Unable to close outfile: %s",
                strerror (errno));
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
    char *prog;
    char  c;

    opterr = 0;                         /* suppress default getopt err msgs */

    prog = (prog = strrchr (argv[0], '/')) ? prog + 1 : argv[0];

    for (;;) {
#ifdef HAVE_GETOPT_LONG
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
//          case 'V':
//              exit (EMUNGE_SUCCESS);
//              break;
            case 'i':
                conf->fn_in = optarg;
                conf->string = NULL;
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
            case '?':
                log_err (EMUNGE_SNAFU, "Invalid option \"%s\"",
                    argv[optind - 1]);
                break;
            default:
                log_err (EMUNGE_SNAFU, "Option \"%s\" not implemented",
                    argv[optind - 1]);
                break;
        }
    }
    if (argv[optind]) {
        log_err (EMUNGE_SNAFU, "Unrecognized parameter \"%s\"", argv[optind]);
    }
    return;
}


void
display_help (char *prog)
{
/*  Displays a help message describing the command-line options.
 */
#ifdef HAVE_GETOPT_LONG
    const int got_long = 1;
#else  /* !HAVE_GETOPT_LONG */
    const int got_long = 0;
#endif /* !HAVE_GETOPT_LONG */
    const int w = -24;                  /* pad for width of option string */

    assert (prog != NULL);

    printf ("Usage: %s [OPTIONS]\n", prog);
    printf ("\n");

    printf ("  %*s %s\n", w, (got_long ? "-h, --help" : "-h"),
            "Display this help");

    printf ("  %*s %s\n", w, (got_long ? "-L, --license" : "-L"),
            "Display license information");

    printf ("  %*s %s\n", w, (got_long ? "-V, --version" : "-V"),
            "Display version information");

    printf ("  %*s %s\n", w, (got_long ? "-i, --input=FILE" : "-i FILE"),
            "Input payload data from FILE");

    printf ("  %*s %s\n", w, (got_long ? "-n, --no-input" : "-n"),
            "Redirect input from /dev/null");

    printf ("  %*s %s\n", w, (got_long ? "-o, --output=FILE" : "-o FILE"),
            "Output credential to FILE");

    printf ("  %*s %s\n", w, (got_long ? "-s, --string=STRING" : "-s STRING"),
            "Input payload data from STRING");

    printf ("\n");
    printf ("By default, data is read from stdin and written to stdout.\n\n");

    return;
}


void
open_files (conf_t conf)
{
    if (conf->fn_in) {
        if (!strcmp (conf->fn_in, "-"))
            conf->fp_in = stdin;
        else if (!(conf->fp_in = fopen (conf->fn_in, "r")))
            log_err (EMUNGE_SNAFU, "Unable to read from \"%s\": %s",
                conf->fn_in, strerror (errno));
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-"))
            conf->fp_out = stdout;
        else if (!(conf->fp_out = fopen (conf->fn_out, "w")))
            log_err (EMUNGE_SNAFU, "Unable to write to \"%s\": %s",
                conf->fn_out, strerror (errno));
    }
    return;
}


void
display_cred (conf_t conf)
{
    if (!conf->fp_out)
        return;
    if (fprintf (conf->fp_out, "%s\n", conf->cred) < 0)
        log_err (EMUNGE_SNAFU, "Write error: %s", strerror (errno));
    return;
}
