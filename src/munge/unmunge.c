/*****************************************************************************
 *  $Id: unmunge.c,v 1.3 2003/02/13 20:22:35 dun Exp $
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
#include <fcntl.h>
#include <munge.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "read.h"


/*****************************************************************************
 *  Options
 *****************************************************************************/

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
struct option opt_table[] = {
    { "help",      0, NULL, 'h' },
    { "license",   0, NULL, 'L' },
    { "version",   0, NULL, 'V' },
    { "input",     1, NULL, 'i' },
    { "metadata",  1, NULL, 'm' },
    { "no-output", 0, NULL, 'n' },
    { "output",    1, NULL, 'o' },
    { "tags",      1, NULL, 't' },
    { "list-tags", 0, NULL, 'T' },
    {  NULL,       0, NULL,  0  }
};
#endif /* HAVE_GETOPT_H */

const char * const opt_string = "hLVi:m:no:t:T";


/*****************************************************************************
 *  Tags
 *****************************************************************************/

typedef enum {
    MUNGE_TAG_STATUS_CODE,
    MUNGE_TAG_STATUS_TEXT,
    MUNGE_TAG_UID,
    MUNGE_TAG_GID,
    MUNGE_TAG_LENGTH,
    MUNGE_TAG_LAST
} munge_tag_t;

typedef struct {
    int   val;
    char *str;
} tag_t;

tag_t munge_tags[] = {
    { MUNGE_TAG_STATUS_CODE, "STATUS-CODE" },
    { MUNGE_TAG_STATUS_TEXT, "STATUS-TEXT" },
    { MUNGE_TAG_UID,         "UID"         },
    { MUNGE_TAG_GID,         "GID"         },
    { MUNGE_TAG_LENGTH,      "LENGTH"      },
    { MUNGE_TAG_LAST,         NULL         }
};


/*****************************************************************************
 *  Configuration
 *****************************************************************************/

struct conf {
    munge_err_t  status;                /* status unmunging the cred         */
    char        *fn_in;                 /* input filename, '-' for stdin     */
    char        *fn_meta;               /* metadata filename, '-' for stdout */
    char        *fn_out;                /* output filename, '-' for stdout   */
    FILE        *fp_in;                 /* input file pointer                */
    FILE        *fp_meta;               /* metadata file pointer             */
    FILE        *fp_out;                /* output file pointer               */
    int          clen;                  /* munged credential length          */
    char        *cred;                  /* munged credential                 */
    int          dlen;                  /* unmunged payload data length      */
    void        *data;                  /* unmunged payload data             */
    uid_t        uid;                   /* process uid according to cred     */
    gid_t        gid;                   /* process gid according to cred     */
    char         tag[MUNGE_TAG_LAST];   /* tag flag array (true if enabled)  */
    int          tag_max_str_len;       /* max strlen of any given tag       */
};

typedef struct conf * conf_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t create_conf (void);
void destroy_conf (conf_t conf);
void parse_cmdline (conf_t conf, int argc, char **argv);
void display_help (char *prog);
void parse_tags (conf_t conf, char *tags);
void display_tags (void);
void open_files (conf_t conf);
void display_meta (conf_t conf);
void display_data (conf_t conf);
int tag_str_to_val (char *str);
char * tag_val_to_str (int val);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t conf;
    int    rc;

    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    rc = read_data_from_file (conf->fp_in,
        (void **) &conf->cred, &conf->clen);
    if (rc < 0)
        log_err (EMUNGE_SNAFU, "%s",
            (errno == ENOMEM) ? strerror (errno) : "Read error");

    conf->status = munge_decode (conf->cred, NULL,
        &conf->data, &conf->dlen, &conf->uid, &conf->gid);

    display_meta (conf);
    display_data (conf);

    destroy_conf (conf);
    exit (conf->status);
}


conf_t
create_conf (void)
{
    conf_t conf;
    int    i;
    int    len;
    int    maxlen;

    if (!(conf = malloc (sizeof (*conf))))
        log_err (EMUNGE_SNAFU, "%s", strerror(errno));

    conf->status = -1;
    conf->fn_in = "-";
    conf->fn_meta = "-";
    conf->fn_out = "-";
    conf->fp_in = NULL;
    conf->fp_meta = NULL;
    conf->fp_out = NULL;
    conf->clen = 0;
    conf->cred = NULL;
    conf->dlen = 0;
    conf->data = NULL;
    conf->uid = -1;
    conf->gid = -1;
    for (i=0, maxlen=0; i<MUNGE_TAG_LAST; i++) {
        conf->tag[i] = 0;
        len = strlen (tag_val_to_str (i));
        maxlen = MAX (maxlen, len);
    }
    conf->tag_max_str_len = maxlen;

    return (conf);
}


void
destroy_conf (conf_t conf)
{
    /*  XXX: Don't free conf's fn_in/fn_meta/fn_out
     *       since they point inside argv[].
     */
    if (conf->fp_in != NULL) {
        if (fclose (conf->fp_in) < 0)
            log_err (EMUNGE_SNAFU, "Unable to close infile: %s",
                strerror (errno));
        conf->fp_in = NULL;
    }
    if (conf->fp_meta != NULL) {
        if (fclose (conf->fp_meta) < 0)
            log_err (EMUNGE_SNAFU, "Unable to close metadata outfile: %s",
                strerror (errno));
        conf->fp_meta = NULL;
    }
    if (conf->fp_out != NULL) {
        if (conf->fn_out && conf->fn_meta
          && strcmp (conf->fn_out, conf->fn_meta))
            if (fclose (conf->fp_out) < 0)
                log_err (EMUNGE_SNAFU, "Unable to close payload outfile: %s",
                    strerror (errno));
        conf->fp_out = NULL;
    }
    if (conf->cred) {
        memset (conf->cred, 0, conf->clen);
        free (conf->cred);
        conf->cred = NULL;
    }
    if (conf->data) {
        memset (conf->data, 0, conf->dlen);
        free (conf->data);
        conf->data = NULL;
    }
    free (conf);
    return;
}


void
parse_cmdline (conf_t conf, int argc, char **argv)
{
    char *prog;
    int   got_tags = 0;
    char  c;
    int   i;

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
                break;
            case 'm':
                conf->fn_meta = optarg;
                break;
            case 'n':
                conf->fn_meta = NULL;
                conf->fn_out = NULL;
                break;
            case 'o':
                conf->fn_out = optarg;
                break;
            case 't':
                got_tags = 1;
                parse_tags (conf, optarg);
                break;
            case 'T':
                display_tags ();
                exit (EMUNGE_SUCCESS);
                break;
            case '?':
                log_err (EMUNGE_SNAFU, "Invalid option \"%s\"",
                    argv[optind - 1]);
                break;
            default:
                log_err (EMUNGE_SNAFU, "Unimplemented option \"%s\"",
                    argv[optind - 1]);
                break;
        }
    }
    if (argv[optind]) {
        log_err (EMUNGE_SNAFU, "Unrecognized parameter \"%s\"", argv[optind]);
    }
    /*  Enable all metadata tags if a subset was not specified.
     */
    if (!got_tags) {
        for (i=0; i<MUNGE_TAG_LAST; i++)
            conf->tag[i] = 1;
    }
    return;
}


void
display_help (char *prog)
{
#ifdef HAVE_GETOPT_LONG
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

    printf ("  %*s %s\n", w, (got_long ? "-i, --input=FILE" : "-i FILE"),
            "Input credential from FILE");

    printf ("  %*s %s\n", w, (got_long ? "-m, --metadata=FILE" : "-m FILE"),
            "Output metadata to FILE");

    printf ("  %*s %s\n", w, (got_long ? "-n, --no-output" : "-n"),
            "Redirect all output to /dev/null");

    printf ("  %*s %s\n", w, (got_long ? "-o, --output=FILE" : "-o FILE"),
            "Output payload to FILE");

    printf ("  %*s %s\n", w, (got_long ? "-t, --tags=STRING" : "-t STRING"),
            "Specify subset of metadata tags to output");

    printf ("  %*s %s\n", w, (got_long ? "-T, --list-tags" : "-T"),
            "Print a list of metadata tags");

    printf ("\n");
    printf ("By default, data is read from stdin and written to stdout.\n\n");

    return;
}


void
parse_tags (conf_t conf, char *tags)
{
    const char *separators = " \t\n.,;";
    char       *tag;
    int         val;

    if (!tags || !*tags)
        return;
    tag = strtok (tags, separators);
    while (tag != NULL) {
        val = tag_str_to_val (tag);
        if (val >= 0)
            conf->tag[val] = 1;
        tag = strtok (NULL, separators);
    }
    return;
}


void
display_tags (void)
{
    int i;

    for (i=0; i<MUNGE_TAG_LAST; i++)
        printf ("%s\n", munge_tags[i].str);
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
    if (conf->fn_meta) {
        if (!strcmp (conf->fn_meta, "-"))
            conf->fp_meta = stdout;
        else if (conf->fn_in && !strcmp (conf->fn_meta, conf->fn_in))
            log_err (EMUNGE_SNAFU,
                "Cannot read and write to the same file \"%s\"",
                conf->fn_meta);
        else if (!(conf->fp_meta = fopen (conf->fn_meta, "w")))
            log_err (EMUNGE_SNAFU, "Unable to write to \"%s\": %s",
                conf->fn_meta, strerror (errno));
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-"))
            conf->fp_out = stdout;
        else if (conf->fn_in && !strcmp (conf->fn_out, conf->fn_in))
            log_err (EMUNGE_SNAFU,
                "Cannot read and write to the same file \"%s\"",
                conf->fn_out);
        else if (conf->fn_meta && !strcmp (conf->fn_out, conf->fn_meta))
            conf->fp_out = conf->fp_meta;
        else if (!(conf->fp_out = fopen (conf->fn_out, "w")))
            log_err (EMUNGE_SNAFU, "Unable to write to \"%s\": %s",
                conf->fn_out, strerror (errno));
    }
    return;
}


void
display_meta (conf_t conf)
{
    int   pad;
    char *s;
    int   w;

    if (!conf->fp_meta)
        return;

    pad = conf->tag_max_str_len + 2;

    if (conf->tag[MUNGE_TAG_STATUS_CODE]) {
        s = tag_val_to_str (MUNGE_TAG_STATUS_CODE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, conf->status);
    }
    if (conf->tag[MUNGE_TAG_STATUS_TEXT]) {
        s = tag_val_to_str (MUNGE_TAG_STATUS_TEXT);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s\n", s, w, 0x20,
            munge_strerror (conf->status));
    }
    if (conf->status != EMUNGE_SUCCESS)
        return;

    if (conf->tag[MUNGE_TAG_UID]) {
        s = tag_val_to_str (MUNGE_TAG_UID);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, conf->uid);
    }
    if (conf->tag[MUNGE_TAG_GID]) {
        s = tag_val_to_str (MUNGE_TAG_GID);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, conf->gid);
    }
    if (conf->tag[MUNGE_TAG_LENGTH]) {
        s = tag_val_to_str (MUNGE_TAG_LENGTH);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, conf->dlen);
    }
    /*  Separate metadata from payload with a newline
     *    if they are both going to the same place.
     */
    if (conf->fp_meta == conf->fp_out) {
        fprintf (conf->fp_meta, "\n");
    }
    /*  XXX: Check fprintf() retvals?
     */
    return;
}


void
display_data (conf_t conf)
{
    if (conf->status != EMUNGE_SUCCESS)
        return;
    if (!conf->fp_out)
        return;
    if (fwrite (conf->data, 1, conf->dlen, conf->fp_out) != conf->dlen)
        log_err (EMUNGE_SNAFU, "Write error");
    return;
}


int
tag_str_to_val (char *str)
{
    int i;

    if (!str || !*str)
        return (-1);
    for (i=0; i<MUNGE_TAG_LAST; i++) {
        if (!strcasecmp (str, munge_tags[i].str))
            return (i);
    }
    return (-1);
}


char *
tag_val_to_str (int val)
{
    int i;

    for (i=0; i<MUNGE_TAG_LAST; i++) {
        if (val == munge_tags[i].val)
            return (munge_tags[i].str);
    }
    return (NULL);
}
