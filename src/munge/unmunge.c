/*****************************************************************************
 *  $Id: unmunge.c,v 1.18 2004/01/29 00:15:49 dun Exp $
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

#include <arpa/inet.h>                  /* for inet_ntoa()                   */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>                      /* for gethostbyaddr()               */
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>                 /* for AF_INET                       */
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <munge.h>
#include "common.h"
#include "read.h"


/*****************************************************************************
 *  Constants
 *****************************************************************************/

#define MAX_TIME_STR 33                 /* YYYY-MM-DD HH:MM:SS (4294967296)  */


/*****************************************************************************
 *  Command-Line Options
 *****************************************************************************/

#if HAVE_GETOPT_H
#  include <getopt.h>
struct option opt_table[] = {
    { "help",         0, NULL, 'h' },
    { "license",      0, NULL, 'L' },
    { "version",      0, NULL, 'V' },
    { "input",        1, NULL, 'i' },
    { "keys",         1, NULL, 'k' },
    { "list-keys",    0, NULL, 'K' },
    { "metadata",     1, NULL, 'm' },
    { "no-output",    0, NULL, 'n' },
    { "output",       1, NULL, 'o' },
    { "socket",       1, NULL, 'S' },
    {  NULL,          0, NULL,  0  }
};
#endif /* HAVE_GETOPT_H */

const char * const opt_string = "hLVi:k:Km:no:S:";


/*****************************************************************************
 *  Metadata Keys
 *****************************************************************************/

typedef struct {
    int   val;
    char *str;
} strval_t;

typedef enum {
    MUNGE_KEY_STATUS,
    MUNGE_KEY_ORIGIN,
    MUNGE_KEY_ENCODE_TIME,
    MUNGE_KEY_DECODE_TIME,
    MUNGE_KEY_TTL,
    MUNGE_KEY_CIPHER_TYPE,
    MUNGE_KEY_MAC_TYPE,   
    MUNGE_KEY_ZIP_TYPE,   
    MUNGE_KEY_UID,
    MUNGE_KEY_GID,
    MUNGE_KEY_LENGTH,
    MUNGE_KEY_LAST
} munge_key_t;

strval_t munge_keys[] = {
    { MUNGE_KEY_STATUS,      "STATUS"  },
    { MUNGE_KEY_ORIGIN,      "ORIGIN"  },
    { MUNGE_KEY_ENCODE_TIME, "ENCODED" },
    { MUNGE_KEY_DECODE_TIME, "DECODED" },
    { MUNGE_KEY_TTL,         "TTL"     },
    { MUNGE_KEY_CIPHER_TYPE, "CIPHER"  },
    { MUNGE_KEY_MAC_TYPE,    "MAC"     },
    { MUNGE_KEY_ZIP_TYPE,    "ZIP"     },
    { MUNGE_KEY_UID,         "UID"     },
    { MUNGE_KEY_GID,         "GID"     },
    { MUNGE_KEY_LENGTH,      "LENGTH"  },
    { MUNGE_KEY_LAST,         NULL     }
};


/*****************************************************************************
 *  Configuration
 *****************************************************************************/

struct conf {
    munge_ctx_t  ctx;                   /* munge context                     */
    munge_err_t  status;                /* error status unmunging the cred   */
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
    char         key[MUNGE_KEY_LAST];   /* key flag array (true if enabled)  */
    int          key_max_str_len;       /* max strlen of any given key       */
};

typedef struct conf * conf_t;


/*****************************************************************************
 *  Prototypes
 *****************************************************************************/

conf_t create_conf (void);
void destroy_conf (conf_t conf);
void parse_cmdline (conf_t conf, int argc, char **argv);
void display_help (char *prog);
void parse_keys (conf_t conf, char *keys);
void display_keys (void);
void open_files (conf_t conf);
void display_meta (conf_t conf);
void display_data (conf_t conf);
int key_str_to_val (char *str);
char * key_val_to_str (int val);


/*****************************************************************************
 *  Functions
 *****************************************************************************/

int
main (int argc, char *argv[])
{
    conf_t       conf;
    int          rc;
    const char  *p;

    if (posignal (SIGPIPE, SIG_IGN) == SIG_ERR)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Unable to ignore signal=%d", SIGPIPE);

    log_open_file (stderr, argv[0], LOG_INFO, LOG_OPT_PRIORITY);
    conf = create_conf ();
    parse_cmdline (conf, argc, argv);
    open_files (conf);

    rc = read_data_from_file (conf->fp_in,
        (void **) &conf->cred, &conf->clen);
    if (rc < 0) {
        if (errno == ENOMEM)
            log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to read input");
        else
            log_err (EMUNGE_SNAFU, LOG_ERR, "Read error");
    }
    conf->status = munge_decode (conf->cred, conf->ctx,
        &conf->data, &conf->dlen, &conf->uid, &conf->gid);

    /*  If the credential is expired, rewound, or replayed, the integrity
     *    of its contents is valid even though the credential itself is not.
     *  As such, display the metadata & payload with an appropriate status
     *    if the integrity checks succeed; o/w, exit out here with an error.
     */
    if  (  (conf->status != EMUNGE_SUCCESS)
        && (conf->status != EMUNGE_CRED_EXPIRED)
        && (conf->status != EMUNGE_CRED_REWOUND)
        && (conf->status != EMUNGE_CRED_REPLAYED) )
    {
        if (!(p = munge_ctx_strerror (conf->ctx)))
            p = munge_strerror (conf->status);
        log_err (conf->status, LOG_ERR, "%s", p);
    }

    display_meta (conf);
    display_data (conf);

    rc = conf->status;
    destroy_conf (conf);
    exit (rc);
}


conf_t
create_conf (void)
{
    conf_t conf;
    int    i;
    int    len;
    int    maxlen;

    if (!(conf = malloc (sizeof (struct conf)))) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf");
    }
    if (!(conf->ctx = munge_ctx_create())) {
        log_errno (EMUNGE_NO_MEMORY, LOG_ERR, "Unable to create conf ctx");
    }
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
    for (i=0, maxlen=0; i<MUNGE_KEY_LAST; i++) {
        conf->key[i] = 0;
        len = strlen (key_val_to_str (i));
        maxlen = MAX (maxlen, len);
    }
    conf->key_max_str_len = maxlen;

    return (conf);
}


void
destroy_conf (conf_t conf)
{
    /*  XXX: Don't free() conf's fn_in/fn_meta/fn_out
     *       since they point inside argv[].
     */
    if (conf->ctx != NULL) {
        munge_ctx_destroy (conf->ctx);
    }
    if (conf->fp_in != NULL) {
        if (fclose (conf->fp_in) < 0)
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to close infile");
        conf->fp_in = NULL;
    }
    if (conf->fp_meta != NULL) {
        if (fclose (conf->fp_meta) < 0)
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to close metadata outfile");
        conf->fp_meta = NULL;
    }
    if (conf->fp_out != NULL) {
        if (conf->fn_out && conf->fn_meta
          && strcmp (conf->fn_out, conf->fn_meta))
            if (fclose (conf->fp_out) < 0)
                log_errno (EMUNGE_SNAFU, LOG_ERR,
                    "Unable to close payload outfile");
        conf->fp_out = NULL;
    }
    if (conf->cred) {
        assert (conf->clen > 0);
        memset (conf->cred, 0, conf->clen);
        free (conf->cred);
        conf->cred = NULL;
    }
    if (conf->data) {
        assert (conf->dlen > 0);
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
    int          got_keys = 0;
    char        *prog;
    int          c;
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
            case 'i':
                conf->fn_in = optarg;
                break;
            case 'k':
                got_keys = 1;
                parse_keys (conf, optarg);
                break;
            case 'K':
                display_keys ();
                exit (EMUNGE_SUCCESS);
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
            case 'S':
                e = munge_ctx_set (conf->ctx, MUNGE_OPT_SOCKET, optarg);
                if (e != EMUNGE_SUCCESS)
                    log_err (EMUNGE_SNAFU, LOG_ERR,
                        "Unable to set munge socket name: %s",
                        munge_ctx_strerror (conf->ctx));
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
    /*  Enable all metadata keys if a subset was not specified.
     */
    if (!got_keys) {
        for (i=0; i<MUNGE_KEY_LAST; i++)
            conf->key[i] = 1;
    }
    return;
}


void
display_help (char *prog)
{
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
            "Input credential from FILE");

    printf ("  %*s %s\n", w, (got_long ? "-m, --metadata=FILE" : "-m FILE"),
            "Output metadata to FILE");

    printf ("  %*s %s\n", w, (got_long ? "-o, --output=FILE" : "-o FILE"),
            "Output payload to FILE");

    printf ("  %*s %s\n", w, (got_long ? "-n, --no-output" : "-n"),
            "Redirect all output to /dev/null");

    printf ("\n");

    printf ("  %*s %s\n", w, (got_long ? "-k, --keys=STRING" : "-k STRING"),
            "Specify subset of metadata keys to output");

    printf ("  %*s %s\n", w, (got_long ? "-K, --list-keys" : "-K"),
            "Print a list of metadata keys");

    printf ("  %*s %s\n", w, (got_long ? "-S, --socket=STRING" : "-S STRING"),
            "Specify local domain socket");

    printf ("\n");
    printf ("By default, data is read from stdin and written to stdout.\n\n");

    return;
}


void
parse_keys (conf_t conf, char *keys)
{
    const char *separators = " \t\n.,;";
    char       *key;
    int         val;

    if (!keys || !*keys)
        return;
    key = strtok (keys, separators);
    while (key != NULL) {
        val = key_str_to_val (key);
        if (val >= 0)
            conf->key[val] = 1;
        key = strtok (NULL, separators);
    }
    return;
}


void
display_keys (void)
{
    int i;

    printf ("Metadata keys:\n\n");
    for (i=0; i<MUNGE_KEY_LAST; i++)
        printf ("  %s\n", munge_keys[i].str);
    printf ("\n");
    return;
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
    if (conf->fn_meta) {
        if (!strcmp (conf->fn_meta, "-"))
            conf->fp_meta = stdout;
        else if (conf->fn_in && !strcmp (conf->fn_meta, conf->fn_in))
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Cannot read and write to the same file \"%s\"",
                conf->fn_meta);
        else if (!(conf->fp_meta = fopen (conf->fn_meta, "w")))
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to write to \"%s\"", conf->fn_meta);
    }
    if (conf->fn_out) {
        if (!strcmp (conf->fn_out, "-"))
            conf->fp_out = stdout;
        else if (conf->fn_in && !strcmp (conf->fn_out, conf->fn_in))
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Cannot read and write to the same file \"%s\"",
                conf->fn_out);
        else if (conf->fn_meta && !strcmp (conf->fn_out, conf->fn_meta))
            conf->fp_out = conf->fp_meta;
        else if (!(conf->fp_out = fopen (conf->fn_out, "w")))
            log_errno (EMUNGE_SNAFU, LOG_ERR,
                "Unable to write to \"%s\"", conf->fn_out);
    }
    return;
}


void
display_meta (conf_t conf)
{
    int             pad;                /* num chars reserved for key field  */
    char           *s;                  /* key field string                  */
    int             w;                  /* width of space chars to fill pad  */
    munge_err_t     e;                  /* munge error condition             */
    struct in_addr  addr;               /* IPv4 addr                         */
    struct hostent *hptr;               /* ptr to static hostent struct      */
    time_t          t;                  /* time (seconds since epoch)        */
    struct tm      *tm_ptr;             /* ptr to broken-down time entry     */
    int             tlen;               /* length of time string             */
    char            tbuf[MAX_TIME_STR]; /* time string buffer                */
    int             i;                  /* all-purpose int                   */
    struct passwd  *pw_ptr;             /* ptr to broken-down password entry */
    struct group   *gr_ptr;             /* ptr to broken-down group entry    */

    if (!conf->fp_meta) {
        return;
    }
    pad = conf->key_max_str_len + 2;

    if (conf->key[MUNGE_KEY_STATUS]) {
        s = key_val_to_str (MUNGE_KEY_STATUS);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_strerror (conf->status), conf->status);
    }
    if (conf->key[MUNGE_KEY_ORIGIN]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_ADDR4, &addr);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve origin ip address: %s",
                munge_ctx_strerror (conf->ctx));
        hptr = gethostbyaddr ((char *) &addr, sizeof (addr), AF_INET);
        s = key_val_to_str (MUNGE_KEY_ORIGIN);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%s)\n", s, w, 0x20,
            (hptr ? hptr->h_name : "???"), inet_ntoa (addr));
    }
    if (conf->key[MUNGE_KEY_ENCODE_TIME]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_ENCODE_TIME, &t);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve encode time: %s",
                munge_ctx_strerror (conf->ctx));
        tm_ptr = localtime (&t);
        tlen = strftime (tbuf, sizeof (tbuf),
            "%Y-%m-%d %H:%M:%S (%s)", tm_ptr);
        if ((tlen == 0) || (tlen >= sizeof (tbuf)))
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                "Overran buffer for encode time");
        s = key_val_to_str (MUNGE_KEY_ENCODE_TIME);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s\n", s, w, 0x20, tbuf);
    }
    if (conf->key[MUNGE_KEY_DECODE_TIME]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_DECODE_TIME, &t);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve decode time: %s",
                munge_ctx_strerror (conf->ctx));
        tm_ptr = localtime (&t);
        tlen = strftime (tbuf, sizeof (tbuf),
            "%Y-%m-%d %H:%M:%S (%s)", tm_ptr);
        if ((tlen == 0) || (tlen >= sizeof (tbuf)))
            log_err (EMUNGE_OVERFLOW, LOG_ERR,
                "Overran buffer for decode time");
        s = key_val_to_str (MUNGE_KEY_DECODE_TIME);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s\n", s, w, 0x20, tbuf);
    }
    if (conf->key[MUNGE_KEY_TTL]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_TTL, &i);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve ttl: %s",
                munge_ctx_strerror (conf->ctx));
        s = key_val_to_str (MUNGE_KEY_TTL);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, i);
    }
    if (conf->key[MUNGE_KEY_CIPHER_TYPE]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_CIPHER_TYPE, &i);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve cipher type: %s",
                munge_ctx_strerror (conf->ctx));
        s = key_val_to_str (MUNGE_KEY_CIPHER_TYPE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_cipher_strings[i], i);
    }
    if (conf->key[MUNGE_KEY_MAC_TYPE]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_MAC_TYPE, &i);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve mesg auth code type: %s",
                munge_ctx_strerror (conf->ctx));
        s = key_val_to_str (MUNGE_KEY_MAC_TYPE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_mac_strings[i], i);
    }
    if (conf->key[MUNGE_KEY_ZIP_TYPE]) {
        e = munge_ctx_get (conf->ctx, MUNGE_OPT_ZIP_TYPE, &i);
        if (e != EMUNGE_SUCCESS)
            log_err (EMUNGE_SNAFU, LOG_ERR,
                "Unable to retrieve compression type: %s",
                munge_ctx_strerror (conf->ctx));
        s = key_val_to_str (MUNGE_KEY_ZIP_TYPE);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            munge_zip_strings[i], i);
    }
    if (conf->key[MUNGE_KEY_UID]) {
        pw_ptr = getpwuid (conf->uid);
        s = key_val_to_str (MUNGE_KEY_UID);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            (pw_ptr ? pw_ptr->pw_name : "???"), conf->uid);
    }
    if (conf->key[MUNGE_KEY_GID]) {
        gr_ptr = getgrgid (conf->gid);
        s = key_val_to_str (MUNGE_KEY_GID);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%s (%d)\n", s, w, 0x20,
            (gr_ptr ? gr_ptr->gr_name : "???"), conf->gid);
    }
    if (conf->key[MUNGE_KEY_LENGTH]) {
        s = key_val_to_str (MUNGE_KEY_LENGTH);
        w = pad - strlen (s);
        fprintf (conf->fp_meta, "%s:%*c%d\n", s, w, 0x20, conf->dlen);
    }
    /*  Since we've been ignoring the return values of fprintf(),
     *    check for errors on fp_meta.
     */
    if (ferror (conf->fp_meta)) {
        log_err (EMUNGE_SNAFU, LOG_ERR, "Write error");
    }
    /*  Separate metadata from payload with a newline
     *    if they are both going to the same place.
     */
    if (conf->fp_meta == conf->fp_out) {
        fprintf (conf->fp_meta, "\n");
    }
    return;
}


void
display_data (conf_t conf)
{
    if ((conf->dlen <= 0) || (!conf->data))
        return;
    if (!conf->fp_out)
        return;
    if (fwrite (conf->data, 1, conf->dlen, conf->fp_out) != conf->dlen)
        log_err (EMUNGE_SNAFU, LOG_ERR, "Write error");
    return;
}


int
key_str_to_val (char *str)
{
    int i;

    if (!str || !*str)
        return (-1);
    for (i=0; i<MUNGE_KEY_LAST; i++) {
        if (!strcasecmp (str, munge_keys[i].str))
            return (i);
    }
    return (-1);
}


char *
key_val_to_str (int val)
{
    int i;

    for (i=0; i<MUNGE_KEY_LAST; i++) {
        if (val == munge_keys[i].val)
            return (munge_keys[i].str);
    }
    return (NULL);
}
